#include "debug_print.h"
#include "analysis_utils.h"
#include "nettypes.h"
#include "avb_1722_common.h"
#include "pcapng.h"
#include "xassert.h"
#include "hwlock.h"

#define MAX_NUM_STREAMS 16

// Class A traffic should have 8k packets per second
#define CLASS_A_PACKETS_PER_SEC 8000

// The standard allows for a variation of +/- 4 packets
#define ERROR_MARGIN 4

stream_state_t stream_state[MAX_NUM_STREAMS];
hwlock_t lock;

static void increment_count(const stream_id_t *id, unsigned int packet_num_bytes,
    unsigned char sequence_number);

void analyse_init()
{
  // Allocate the hardware lock that will be used to guard access to shared state
  lock = hwlock_alloc();
}

void analyse_buffer(const unsigned char *buffer, const unsigned int length_in_bytes)
{
  enhanced_packet_block_t *epb = (enhanced_packet_block_t *)buffer;

  uint16_t ethertype;
  void *payload;

  ethernet_hdr_t *hdr = (ethernet_hdr_t *) &(epb->data);
  ethertype = ntoh16(hdr->ethertype);

  // Packet must be VLAN tagged
  if (ethertype != 0x8100)
    return;

  tagged_ethernet_hdr_t *tagged_hdr = (tagged_ethernet_hdr_t *) &(epb->data);
  ethertype = ntoh16(tagged_hdr->ethertype);
  payload = &(tagged_hdr->payload);

  if (ethertype != AVB_1722_ETHERTYPE)
    return;

  AVB_DataHeader_t *avb_hdr = (AVB_DataHeader_t *)payload;
  unsigned int subtype = AVBTP_SUBTYPE(avb_hdr);
  if (subtype == 0) {
    stream_id_t id;
    id.low  = AVBTP_STREAM_ID0(avb_hdr);
    id.high = AVBTP_STREAM_ID1(avb_hdr);

    if (id.low != 0 || id.high != 0) {
      unsigned char sequence_number = AVBTP_SEQUENCE_NUMBER(avb_hdr);
      increment_count(&id, epb->packet_len, sequence_number);
    }
  }
}

void check_counts(int oversubscribed, int debug)
{
  // First pass to snapshot the current counts
  for (unsigned int i = 0; i < MAX_NUM_STREAMS; i++) {
    stream_state_t *state = &stream_state[i];

    state->active = ((state->last_count != 0) && (state->count != 0));
    state->last_count = state->snapshot;

    // Ensure the read/modify of count is atomic
    hwlock_acquire(lock);
    state->snapshot = state->count;
    state->count = 0;
    hwlock_release(lock);
  }

  int num_active = 0;
  // Second pass to do the checking and printing
  for (unsigned int i = 0; i < MAX_NUM_STREAMS; i++) {
    stream_state_t *state = &stream_state[i];

    if (state->id.low || state->id.high) {
      if (state->snapshot == 0) {
        debug_printf("Removing stream 0x%x%x\n", state->id.high, state->id.low);
        hwlock_acquire(lock);
        state->id.high = 0;
        state->id.low = 0;
        hwlock_release(lock);

      } else {
        unsigned int expected_rate = CLASS_A_PACKETS_PER_SEC;
        num_active++;

        if (oversubscribed) {
          // When the stream is oversubscribed then there will be an extra byte
          // of bandwidth allocated per packet.
          const unsigned int preamble_bytes = 8;
          const unsigned int ifg_bytes = 96/8; // InterFrameGap = 96 bit-times

          // The one extra byte is for the entire frame (data + preamble + IFG)
          unsigned int num_bytes = state->packet_num_bytes +
                                      preamble_bytes + ifg_bytes;
          expected_rate = expected_rate * (num_bytes + 1) / num_bytes; 
        }

        // Need to check the value of last_count because otherwise there are
        // spurious errors when the stream is stopping.
        if (state->active &&
            (state->last_count < (expected_rate - ERROR_MARGIN) ||
             state->last_count > (expected_rate + ERROR_MARGIN)))
        {
          debug_printf("ERROR: 0x%x%x had %d packets in the last second\n", state->id.high, state->id.low,
              state->last_count);
        } else if (debug) {
          debug_printf("0x%x%x %d\n", state->id.high, state->id.low,
              state->last_count);
        }
      }
    }
  }

  if (debug && num_active == 0)
    debug_printf("No active streams found\n");
}

static void increment_count(const stream_id_t *id, unsigned int packet_num_bytes,
    unsigned char sequence_number)
{
  unsigned int free_index = MAX_NUM_STREAMS;
  hwlock_acquire(lock);
  for (unsigned int i = 0; i < MAX_NUM_STREAMS; i++) {
    stream_state_t *state = &stream_state[i];

    if ((id->low  == state->id.low) &&
        (id->high == state->id.high)) {
      state->count++;

      if (state->packet_num_bytes != packet_num_bytes) {
        debug_printf("ERROR stream 0x%x%x packet size changed from %d to %d\n",
            state->id.high, state->id.low,
            state->packet_num_bytes, packet_num_bytes);
      }
      if (state->sequence_number != sequence_number) {
        debug_printf("ERROR stream 0x%x%x sequence expected %d got %d\n",
            state->id.high, state->id.low,
            state->sequence_number, sequence_number);
      }
      state->sequence_number = sequence_number + 1;
      goto increment_count_done;

    } else if ((state->id.low  == 0) &&
               (state->id.high == 0)) {
      free_index = i;
    }
  }

  if (free_index != MAX_NUM_STREAMS) {
    stream_state_t *state = &stream_state[free_index];
    state->id.low  = id->low;
    state->id.high = id->high;
    state->count = 1;
    state->snapshot = 0;
    state->packet_num_bytes = packet_num_bytes;
    state->sequence_number = sequence_number + 1;
    debug_printf("Adding stream 0x%x%x\n", state->id.high, state->id.low);
  } else {
    assert(0); // Can't track this stream - no free slots available
  }
increment_count_done:
  hwlock_release(lock);
}

