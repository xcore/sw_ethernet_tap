
#include "analysis_tile.h"

#include "buffers.h"
#include "util.h"
#include "analysis_utils.h"
#include "debug_print.h"
#include "xassert.h"
#include <xs1.h>

#define TIMER_TICKS_PER_SECOND 100000000

void analysis_control(chanend c_receiver_to_control, chanend c_control_to_analysis,
    chanend c_outputter_to_control)
{
  buffers_used_t used_buffers;
  buffers_used_initialise(used_buffers);

  buffers_free_t free_buffers;
  buffers_free_initialise(free_buffers);

  //start by issuing buffers to both of the miis
  c_receiver_to_control <: buffers_free_acquire(free_buffers);

  int analysis_active = 0;
  int work_pending = 0;
  while (1) {
    select {
      case c_receiver_to_control :> uintptr_t buffer : {
        unsigned length_in_bytes;
        c_receiver_to_control :> length_in_bytes;

        if (buffers_used_full(used_buffers) || free_buffers.top_index == 0) {
          // No more buffers
          assert(0);
        } else {
          buffers_used_add(used_buffers, buffer, length_in_bytes);
          work_pending++;
          c_receiver_to_control <: buffers_free_acquire(free_buffers);
        }
        break;
      }
      case c_outputter_to_control :> uintptr_t buffer : {
        // Buffer fully processed - release it
        buffers_free_release(free_buffers, buffer);
        break;
      }
      case analysis_active => c_control_to_analysis :> uintptr_t buffer : {
        // Analysis complete - can pass it another buffer
        analysis_active = 0;
        break;
      }
      work_pending && !analysis_active => default : {
        // send a pointer out to the analyser
        uintptr_t buffer;
        unsigned length_in_bytes;
        {buffer, length_in_bytes} = buffers_used_take(used_buffers);
        master {
          c_control_to_analysis <: buffer;
          c_control_to_analysis <: length_in_bytes;
        }
        work_pending--;
        analysis_active = 1;
        break;
      }
    }
  }
}

void buffer_receiver(chanend c_inter_tile, chanend c_receiver_to_control)
{
  uintptr_t buffer;

  while (1) {
    // Get buffer pointer from control
    c_receiver_to_control :> buffer;

    unsigned length_in_bytes;
    c_inter_tile :> length_in_bytes;
    assert(length_in_bytes < MAX_BUFFER_SIZE);

    unsigned int length_in_words = (length_in_bytes + 3) / 4;
    slave {
      for (unsigned i = 0; i < length_in_words; i++) {
        unsigned int tmp;
        c_inter_tile :> tmp;
        asm volatile("stw %0, %1[%2]"::"r"(tmp), "r"(buffer), "r"(i):"memory");
      }
    }

    // Send on complete buffer
    c_receiver_to_control <: buffer;
    c_receiver_to_control <: length_in_bytes;
  }
}

void analyser(chanend c_control_to_analysis, chanend c_analysis_to_outputter)
{
  while (1) {
    uintptr_t buffer;
    unsigned length_in_bytes;
    slave {
      c_control_to_analysis :> buffer;
      c_control_to_analysis :> length_in_bytes;
    }
    unsafe {
      analyse_buffer((unsigned char *)buffer, length_in_bytes);
    }

    // Pass the buffer on to the outputter
    c_analysis_to_outputter <: buffer;
    c_analysis_to_outputter <: length_in_bytes;

    // Tell the control the analysis is ready for the next buffer
    c_control_to_analysis <: buffer;
  }
}

void xscope_outputter(server interface outputter_config i_config,
    chanend c_analysis_to_outputter, chanend c_outputter_to_control)
{
  int send_packets_over_xscope = 0;

  while (1) {
    uintptr_t buffer;
    select {
      case c_analysis_to_outputter :> buffer : {
        unsigned length_in_bytes;
        c_analysis_to_outputter :> length_in_bytes;
        unsafe {
          if (send_packets_over_xscope)
            xscope_bytes_c(0, length_in_bytes, (unsigned char *)buffer);
        }
        c_outputter_to_control <: buffer;
        break;
      }
      case i_config.set_output_packets(int enabled) : {
        send_packets_over_xscope = enabled;
        debug_printf("xscope packet output %s\n", enabled ? "enabled" : "disabled");
        break;
      }
    }
  }
}

void periodic_checks(server interface analysis_config i_config)
{
  unsigned int expect_oversubscribed = 0;
  timer tmr;
  int time;

  tmr :> time;
  time += TIMER_TICKS_PER_SECOND;

  while (1) {
    select {
      case tmr when timerafter(time) :> void : {
        time += TIMER_TICKS_PER_SECOND;
        check_counts(expect_oversubscribed);
        break;
      }
      case i_config.set_expect_oversubscribed(int oversubscribed) : {
        expect_oversubscribed = oversubscribed;
        debug_printf("Expecting %s\n",
            expect_oversubscribed ? "oversubscribed" : "normal");
        break;
      }
    }
  }
}

