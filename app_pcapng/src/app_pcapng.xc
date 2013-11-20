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
#include "debug_print.h"

#define SEND_PACKET_DATA 1

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
    buffers_used_t &used_buffers, buffers_free_t &free_buffers, uintptr_t buffer,
    int &waiting_for_buffer, streaming chanend debug)
{
  unsigned length_in_bytes;
  c :> length_in_bytes;

  buffers_used_add(used_buffers, buffer, length_in_bytes);
  work_pending++;

  if (buffers_used_full(used_buffers) || free_buffers.top_index == 0) {
    debug <: 0;
    waiting_for_buffer++;
  } else {
    c <: buffers_free_acquire(free_buffers);
  }
}

static void control(streaming chanend c_mii1, streaming chanend c_mii2,
    streaming chanend c_control_to_outputter, streaming chanend debug)
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
  int waiting_for_buffer1 = 0;
  int waiting_for_buffer2 = 0;
  while (1) {
    select {
      case c_mii1 :> uintptr_t buffer : {
        process_received(c_mii1, work_pending, used_buffers, free_buffers, buffer, waiting_for_buffer1, debug);
        break;
      }
      case c_mii2 :> uintptr_t buffer : {
        process_received(c_mii2, work_pending, used_buffers, free_buffers, buffer, waiting_for_buffer2, debug);
        break;
      }
      case sender_active => c_control_to_outputter :> uintptr_t sent_buffer : {
        sender_active = 0;

        if (waiting_for_buffer1) {
          c_mii1 <: sent_buffer;
          waiting_for_buffer1--;
        } else if (waiting_for_buffer2) {
          c_mii2 <: sent_buffer;
          waiting_for_buffer2--;
        } else {
          buffers_free_release(free_buffers, sent_buffer);
        }
        break;
      }
      work_pending && !sender_active => default : {
        // Send a pointer out to the outputter
        uintptr_t buffer;
        unsigned length_in_bytes;
        {buffer, length_in_bytes} = buffers_used_take(used_buffers);
        c_control_to_outputter <: buffer;
        c_control_to_outputter <: length_in_bytes;
        work_pending--;
        sender_active = 1;
        break;
      }
    }
  }
}

static void xscope_outputter(streaming chanend c_control_to_outputter)
{
  while (1) {
    uintptr_t buffer;
    unsigned length_in_bytes;

    c_control_to_outputter :> buffer;
    c_control_to_outputter :> length_in_bytes;

    unsafe {
      xscope_bytes_c(0, length_in_bytes, (unsigned char *)buffer);
    }

    c_control_to_outputter <: buffer;
  }
}

void xscope_user_init(void) {
  xscope_register(1, XSCOPE_CONTINUOUS, "Packet Data", XSCOPE_UINT, "Value");
  xscope_config_io(XSCOPE_IO_BASIC);
}

void debugger(streaming chanend c)
{
  int lost_count = 0;
  int printed_count = 0;

  while (1) {
    select {
      case c :> int x:
        lost_count++;
        break;

      default:
        if (printed_count != lost_count) {
          debug_printf("\r%d.", lost_count);
          printed_count = lost_count;
        }
        break;
    }
  }
}

enum {
  TIMER_CLIENT0 = 0,
  TIMER_CLIENT1,
  NUM_TIMER_CLIENTS
} timer_clients;

int main()
{
  streaming chan debug;
  streaming chan c_mii1;
  streaming chan c_mii2;
  streaming chan c_time_server[NUM_TIMER_CLIENTS];
  streaming chan c_control_to_outputter;
  par {
    on tile[1]:xscope_outputter(c_control_to_outputter);
    on tile[1]:control(c_mii1, c_mii2, c_control_to_outputter, debug);
    on tile[1]:pcapng_receiver(c_mii1, mii1, c_time_server[TIMER_CLIENT0]);
    on tile[1]:pcapng_receiver(c_mii2, mii2, c_time_server[TIMER_CLIENT1]);
    on tile[1]:pcapng_timer_server(c_time_server, NUM_TIMER_CLIENTS);

    on tile[0]:debugger(debug);
  }
  return 0;
}

