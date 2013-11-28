#include "receiver_tile.h"

#include "receiver.h"
#include "buffers.h"
#include "xassert.h"
#include "ethernet_tap.h"

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

void receiver_control(streaming chanend c_mii1, streaming chanend c_mii2,
    streaming chanend c_control_to_sender)
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
        c_control_to_sender <: buffer;
        c_control_to_sender <: length_in_bytes;
        work_pending--;
        sender_active = 1;
        break;
      }
    }
  }
}

void buffer_sender(streaming chanend c_control_to_sender, chanend c_inter_tile)
{
  while (1) {
    uintptr_t buffer;
    unsigned length_in_bytes;

    c_control_to_sender :> buffer;
    c_control_to_sender :> length_in_bytes;

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

void relay_control(server interface ethernet_tap_relay_control i_relay_control)
{
  while (1) {
    select {
      case i_relay_control.set_relay_open() : {
        ethernet_tap_set_relay_open();
        break;
      }
      case i_relay_control.set_relay_close() : {
        ethernet_tap_set_relay_close();
        break;
      }
    }
  }
}
