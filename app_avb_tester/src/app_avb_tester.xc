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

void control(chanend c_mii1, chanend c_mii2, chanend c_sender)
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
      case sender_active => c_sender :> uintptr_t buffer : {
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
          c_sender <: buffer;
          c_sender <: length_in_bytes;
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
void buffer_sender(chanend c_analyser, chanend c_sender)
{
  while (1) {
    uintptr_t buffer;
    unsigned length_in_bytes;

    slave {
      c_sender :> buffer;
      c_sender :> length_in_bytes;
    }

    unsigned int length_in_words = (length_in_bytes + 3) / 4;
    c_analyser <: length_in_words;
    master {
      for (unsigned i = 0; i < length_in_words; i++) {
        unsigned tmp;
        asm volatile("ldw %0, %1[%2]":"=r"(tmp):"r"(buffer), "r"(i):"memory");
        c_analyser <: tmp;
      }
    }
    c_sender <: buffer;
  }
}

void analyser(chanend c_analyser)
{
  unsigned int buffer[MAX_BUFFER_SIZE];
  unsigned length_in_words;
  while (1) {
    c_analyser :> length_in_words;
    slave {
      for (unsigned i = 0; i < length_in_words; i++)
        c_analyser :> buffer[i];
    }
    analyse(buffer);
  }
}

void periodic_checks()
{
  timer tmr;
  int time;
  tmr :> time;

  while (1) {
    time += 100000000;
    tmr when timerafter(time) :> void;
    check_counts();
  }
}

void xscope_user_init()
{
  xscope_register(0, 0, "", 0, "");
  xscope_config_io(XSCOPE_IO_BASIC);
}

int main()
{
  chan c_mii1;
  chan c_mii2;
  chan c_analyser;
  chan c_sender;
  interface pcapng_timer_interface i_tmr[NUM_TIMER_CLIENTS];
  par {
    on tile[0]: {
      analyse_init();
      par {
        periodic_checks();
        analyser(c_analyser);
      }
    }
    on tile[1]:buffer_sender(c_analyser, c_sender);
    on tile[1]:control(c_mii1, c_mii2, c_sender);
    on tile[1]:pcapng_receiver(c_mii1, mii1, i_tmr[0]);
    on tile[1]:pcapng_receiver(c_mii2, mii2, i_tmr[1]);
    on tile[1]:pcapng_timer_server(i_tmr, NUM_TIMER_CLIENTS);
  }
  return 0;
}

