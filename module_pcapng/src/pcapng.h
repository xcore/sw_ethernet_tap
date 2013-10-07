#ifndef __PCAPNG_H__
#define __PCAPNG_H__

#ifdef __XC__
extern "C" {
#endif

enum pcap_ng_block_type_t {
  PCAPNG_BLOCK_SECTION_HEADER        = 0x0A0D0D0A,
  PCAPNG_BLOCK_INTERFACE_DESCRIPTION = 1,
  PCAPNG_BLOCK_SIMPLE_PACKET         = 3,
  PCAPNG_BLOCK_NAME_RESOLUTION       = 4,
  PCAPNG_BLOCK_ENHANCED_PACKET       = 6,
};

typedef struct section_block_header_t {
    uint32_t block_type;
    uint32_t block_total_len_pre;
    uint32_t byte_order_magic;
    uint16_t major_version;
    uint16_t minor_version;
    uint64_t section_length;
    uint32_t options;
    uint32_t block_total_len_post;
} section_block_header_t;

typedef struct option_if_tsresol_t {
    uint16_t type;
    uint16_t length;
    uint8_t value;
} option_if_tsresol_t;

typedef struct interface_description_block_t {
    uint32_t block_type;
    uint32_t block_total_len_pre;
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snap_len;
    option_if_tsresol_t if_tsresol;
    uint32_t block_total_len_post;
} interface_description_block_t;

typedef struct enhanced_packet_block_t {
    uint32_t block_type;
    uint32_t block_total_len_pre;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t packet_len;
    uint32_t *data;
    uint32_t *options;
    uint32_t block_total_len_post;
} enhanced_packet_block_t;

// The overhead of the Enhanced Packet Block structure (everything but the data pointer)
#define PCAPNG_EPB_OVERHEAD_BYTES (sizeof(enhanced_packet_block_t) - sizeof(((enhanced_packet_block_t*)0)->data))

#ifdef __XC__
}
#endif

#endif // __PCAPNG_H__
