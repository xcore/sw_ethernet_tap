#include <platform.h>
#include <xscope.h>
#include <stdint.h>
#include <print.h>
#include <xclib.h>
#include "util.h"
#include "xassert.h"
#include "receiver.h"
#include "buffers.h"
#include "pcapng.h"
#include "pcapng_conf.h"

#define SEND_PACKET_DATA 1

#define NUM_TIMER_CLIENTS 2

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

static inline void process_received(streaming chanend c, int &work_pending,
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

void control(streaming chanend c_mii1, streaming chanend c_mii2, chanend c_control_to_outputter)
{
  buffers_used_t used_buffers;
  buffers_used_initialise(used_buffers);

  buffers_free_t free_buffers;
  buffers_free_initialise(free_buffers);

  // Start by issuing buffers to both of the miis
  c_mii1 <: buffers_free_acquire(free_buffers);
  c_mii2 <: buffers_free_acquire(free_buffers);

  // Give a second buffer to ensure no delay between packets
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
      case sender_active => c_control_to_outputter :> uintptr_t sent_buffer : {
        buffers_free_release(free_buffers, sent_buffer);
        sender_active = 0;
        break;
      }
      work_pending && !sender_active => default : {
        // Send a pointer out to the outputter
        uintptr_t buffer;
        unsigned length_in_bytes;
        {buffer, length_in_bytes} = buffers_used_take(used_buffers);
        master {
          c_control_to_outputter <: buffer;
          c_control_to_outputter <: length_in_bytes;
        }
        work_pending--;
        sender_active = 1;
        break;
      }
    }
  }
}

void xscope_outputter(chanend c_control_to_outputter)
{
  while (1) {
    uintptr_t buffer;
    unsigned length_in_bytes;

    slave {
      c_control_to_outputter :> buffer;
      c_control_to_outputter :> length_in_bytes;
    }
    xscope_bytes_c(0, length_in_bytes, buffer);

    c_control_to_outputter <: buffer;
  }
}

void xscope_user_init(void) {
  xscope_register(1, XSCOPE_CONTINUOUS, "Packet Data", XSCOPE_UINT, "Value");
}

int main()
{
  streaming chan c_mii1;
  streaming chan c_mii2;
  chan c_control_to_outputter;
  interface pcapng_timer_interface i_tmr[NUM_TIMER_CLIENTS];
  par {
    on tile[1]:xscope_outputter(c_control_to_outputter);
    on tile[1]:control(c_mii1, c_mii2, c_control_to_outputter);
    on tile[1]:pcapng_receiver(c_mii1, mii1, i_tmr[0]);
    on tile[1]:pcapng_receiver(c_mii2, mii2, i_tmr[1]);
    on tile[1]:pcapng_timer_server(i_tmr, NUM_TIMER_CLIENTS);
  }
  return 0;
}

