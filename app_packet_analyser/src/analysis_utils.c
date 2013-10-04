#include "debug_print.h"
#include "analysis_utils.h"
#include "pcapng.h"
#include "xassert.h"
#include "hwlock.h"
#include "util.h"

#define NUM_INTERFACES 2

interface_state_t interface_state[NUM_INTERFACES];
hwlock_t lock;

void analyse_init()
{
  // Allocate the hardware lock that will be used to guard access to shared state
  lock = hwlock_alloc();

  for (unsigned int i = 0; i < NUM_INTERFACES; i++)
    interface_state[i].interface_id = i;
}

void analyse_buffer(const unsigned char *buffer)
{
  enhanced_packet_block_t *epb = (enhanced_packet_block_t *)buffer;

  int interface_id = epb->interface_id;

  xassert(interface_id < NUM_INTERFACES);
  hwlock_acquire(lock);
  interface_state[interface_id].packet_count += 1;
  interface_state[interface_id].byte_count += epb->packet_len;
  hwlock_release(lock);
}

void check_counts()
{
  // First pass to snapshot the current counts
  hwlock_acquire(lock);
  for (unsigned int i = 0; i < NUM_INTERFACES; i++) {
    interface_state[i].byte_snapshot = interface_state[i].byte_count;
    interface_state[i].total_byte_count += interface_state[i].byte_count;
    interface_state[i].byte_count = 0;

    interface_state[i].packet_snapshot = interface_state[i].packet_count;
    interface_state[i].total_packet_count += interface_state[i].packet_count;
    interface_state[i].packet_count = 0;
  }
  hwlock_release(lock);

  // Second pass to do the printing
  for (unsigned int i = 0; i < NUM_INTERFACES; i++) {
    xscope_bytes_c(0, sizeof(interface_state[i]), (unsigned char *)&interface_state[i]);
  }
}

