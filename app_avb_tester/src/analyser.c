#include "debug_print.h"
#include "analyser.h"
#include "nettypes.h"
#include "avb_1722_common.h"
#include "pcapng.h"
#include "xassert.h"
#include "hwlock.h"

#define MAX_NUM_STREAMS 16

stream_count_t stream_counts[MAX_NUM_STREAMS];
hwlock_t lock;

void analyse_init()
{
  lock = hwlock_alloc();
}

void increment_count(const stream_id_t *id)
{
  unsigned int free_index = MAX_NUM_STREAMS;
  hwlock_acquire(lock);
  for (unsigned int i = 0; i < MAX_NUM_STREAMS; i++) {
    if ((id->low  == stream_counts[i].id.low) &&
        (id->high == stream_counts[i].id.high)) {
      stream_counts[i].count++;
      goto increment_count_done;
      
    } else if ((stream_counts[i].id.low  == 0) &&
               (stream_counts[i].id.high == 0)) {
      free_index = i;
    }
  }

  if (free_index != MAX_NUM_STREAMS) {
    stream_counts[free_index].id.low  = id->low;
    stream_counts[free_index].id.high = id->high;
    stream_counts[free_index].count = 1;
    stream_counts[free_index].last_count = 0;
    debug_printf("Adding stream 0x%x%x\n", stream_counts[free_index].id.high, stream_counts[free_index].id.low);
  } else {
    assert(0); // Can't track this stream - no free slots available
  }
increment_count_done:
  hwlock_release(lock);
}

void analyse(const unsigned char *buffer, const unsigned int length_in_bytes)
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

    if (id.low != 0 || id.high != 0)
      increment_count(&id);
  }
}

void check_counts(unsigned int now)
{
  // First iteration to quickly grab the current counts
  for (unsigned int i = 0; i < MAX_NUM_STREAMS; i++) {
    stream_counts[i].snapshot = stream_counts[i].count - stream_counts[i].last_count;
    stream_counts[i].last_count = stream_counts[i].count;
  }

  debug_printf("----\n", now);
  // Second iteration to do the printing
  for (unsigned int i = 0; i < MAX_NUM_STREAMS; i++) {
    if (stream_counts[i].id.low || stream_counts[i].id.high) {
      if (stream_counts[i].snapshot == 0) {
        debug_printf("Removing stream 0x%x%x\n", stream_counts[i].id.high, stream_counts[i].id.low);
        hwlock_acquire(lock);
        stream_counts[i].id.high = 0;
        stream_counts[i].id.low = 0;
        hwlock_release(lock);

      } else {
        debug_printf("0x%x%x %d\n", stream_counts[i].id.high, stream_counts[i].id.low, 
            stream_counts[i].snapshot);
      }
    }
  }
}

