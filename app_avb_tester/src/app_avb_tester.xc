#include <platform.h>
#include <xscope.h>
#include <stdint.h>
#include <print.h>
#include <xclib.h>
#include "xassert.h"
#include "receiver.h"
#include "buffers.h"
#include "pcapng.h"
#include "pcapng_conf.h"
#include "analyser.h"
#include "util.h"

#define SEND_PACKETS_OVER_XSCOPE 0

enum {
  TIMER_CLIENT0 = 0,
  TIMER_CLIENT1,
  NUM_TIMER_CLIENTS
} timer_clients;

// Circle slot
on tile[1]: pcapng_mii_rx_t mii2 = {
  1,
  XS1_CLKBLK_3,
  XS1_PORT_1B,
  XS1_PORT_4A,
  XS1_PORT_1C,
};

// Square slot
on tile[1]: pcapng_mii_rx_t mii1 = {
  0,
  XS1_CLKBLK_4,
  XS1_PORT_1J,
  XS1_PORT_4E,
  XS1_PORT_1K,
};

static inline void process_received(chanend c, int &work_pending,
    buffers_used_t &used_buffers, buffers_free_t &free_buffers, uintptr_t buffer)
{
  unsigned length_in_bytes;
  c :> length_in_bytes;

  if (buffers_used_full(used_buffers) || free_buffers.top_index == 0) {
    // No more buffers
    assert(0);
  } else {
    buffers_used_add(used_buffers, buffer, length_in_bytes);
    work_pending++;
    c <: buffers_free_acquire(free_buffers);
  }
}

void receiver_control(chanend c_mii1, chanend c_mii2, chanend c_control_to_sender)
{
  buffers_used_t used_buffers;
  buffers_used_initialise(used_buffers);

  buffers_free_t free_buffers;
  buffers_free_initialise(free_buffers);

  //start by issuing buffers to both of the miis
  c_mii1 <: buffers_free_acquire(free_buffers);
  c_mii2 <: buffers_free_acquire(free_buffers);

  int sender_active = 0;
  int work_pending = 0;
  while (1) {
    select {
      case c_mii1 :> uintptr_t buffer : {
        process_received(c_mii1, work_pending, used_buffers, free_buffers, buffer);
        break;
      }
      case c_mii2 :> uintptr_t buffer : {
        process_received(c_mii2, work_pending, used_buffers, free_buffers, buffer);
        break;
      }
      case sender_active => c_control_to_sender :> uintptr_t buffer : {
        buffers_free_release(free_buffers, buffer);
        sender_active = 0;
        break;
      }
      work_pending && !sender_active => default : {
        // Send a pointer out to the outputter
        uintptr_t buffer;
        unsigned length_in_bytes;
        {buffer, length_in_bytes} = buffers_used_take(used_buffers);
        master {
          c_control_to_sender <: buffer;
          c_control_to_sender <: length_in_bytes;
        }
        work_pending--;
        sender_active = 1;
        break;
      }
    }
  }
}

/*
 * Takes buffer pointers and passes the full packets to the xscope core on tile 0
 */
void buffer_sender(chanend c_control_to_sender, chanend c_inter_tile)
{
  while (1) {
    uintptr_t buffer;
    unsigned length_in_bytes;

    slave {
      c_control_to_sender :> buffer;
      c_control_to_sender :> length_in_bytes;
    }

    unsigned int length_in_words = (length_in_bytes + 3) / 4;
    c_inter_tile <: length_in_bytes;
    master {
      for (unsigned i = 0; i < length_in_words; i++) {
        unsigned tmp;
        asm volatile("ldw %0, %1[%2]":"=r"(tmp):"r"(buffer), "r"(i):"memory");
        c_inter_tile <: tmp;
      }
    }
    c_control_to_sender <: buffer;
  }
}

void analysis_control(chanend c_receiver_to_control, chanend c_control_to_analysis, chanend c_outputter_to_control)
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
        // send a pointer out to the outputter
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
    analyse(buffer, length_in_bytes);
    master {
      // Pass the buffer on to the outputter
      c_analysis_to_outputter <: buffer;
      c_analysis_to_outputter <: length_in_bytes;
    }
    // Tell the control the analysis is ready for the next buffer
    c_control_to_analysis <: buffer;
  }
}

void xscope_outputter(chanend c_analysis_to_outputter, chanend c_outputter_to_control)
{
  while (1) {
    uintptr_t buffer;
    unsigned length_in_bytes;
    slave {
      c_analysis_to_outputter :> buffer;
      c_analysis_to_outputter :> length_in_bytes;
    }
    if (SEND_PACKETS_OVER_XSCOPE)
      xscope_bytes_c(0, length_in_bytes, buffer);
    c_outputter_to_control <: buffer;
  }
}

void periodic_checks()
{
  timer tmr;
  int time;
  tmr :> time;

  while (1) {
    unsigned int now;
    time += 100000000;
    tmr when timerafter(time) :> now;
    check_counts(now);
  }
}

void xscope_user_init()
{
  if (SEND_PACKETS_OVER_XSCOPE)
    xscope_register(1, XSCOPE_CONTINUOUS, "Packet Data", XSCOPE_UINT, "Value");
  else
    xscope_register(0, 0, "", 0, "");

  xscope_config_io(XSCOPE_IO_BASIC);
}

int main()
{
  chan c_inter_tile;
  par {
    on tile[0]: {
      // All the analysis on tile[0]
      chan c_receiver_to_control;
      chan c_control_to_analysis;
      chan c_analysis_to_outputter;
      chan c_outputter_to_control;

      analyse_init();
      par {
        buffer_receiver(c_inter_tile, c_receiver_to_control);
        analysis_control(c_receiver_to_control, c_control_to_analysis, c_outputter_to_control);
        analyser(c_control_to_analysis, c_analysis_to_outputter);
        xscope_outputter(c_analysis_to_outputter, c_outputter_to_control);
        periodic_checks();
      }
    }

    on tile[1] : {
      // Packet reception is done on tile[1]
      chan c_mii1;
      chan c_mii2;
      chan c_control_to_sender;
      interface pcapng_timer_interface i_tmr[NUM_TIMER_CLIENTS];

      par {
        buffer_sender(c_control_to_sender, c_inter_tile);
        receiver_control(c_mii1, c_mii2, c_control_to_sender);
        pcapng_receiver(c_mii1, mii1, i_tmr[TIMER_CLIENT0]);
        pcapng_receiver(c_mii2, mii2, i_tmr[TIMER_CLIENT1]);
        pcapng_timer_server(i_tmr, NUM_TIMER_CLIENTS);
      }
    }
  }
  return 0;
}

