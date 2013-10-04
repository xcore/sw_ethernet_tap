
#include "analysis_tile.h"

#include "buffers.h"
#include "analysis_utils.h"
#include "debug_print.h"
#include "xassert.h"
#include <xs1.h>

#define TIMER_TICKS_PER_SECOND 100000000

void analysis_control(chanend c_receiver_to_control, chanend c_control_to_analysis)
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
      case analysis_active => c_control_to_analysis :> uintptr_t buffer : {
        // Analysis complete - release the buffer
        analysis_active = 0;
        buffers_free_release(free_buffers, buffer);
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

void analyser(chanend c_control_to_analysis)
{
  while (1) {
    uintptr_t buffer;
    unsigned length_in_bytes;
    slave {
      c_control_to_analysis :> buffer;
      c_control_to_analysis :> length_in_bytes;
    }
    analyse_buffer(buffer);

    // Tell the control the analysis is ready for the next buffer
    c_control_to_analysis <: buffer;
  }
}

void periodic_checks(server interface analysis_config i_config)
{
  timer tmr;
  int time;

  tmr :> time;
  time += TIMER_TICKS_PER_SECOND;

  while (1) {
    select {
      case tmr when timerafter(time) :> void : {
        time += TIMER_TICKS_PER_SECOND;
        check_counts();
        break;
      }
    }
  }
}

