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
    unsigned int block_type;
    unsigned int block_total_len_pre;
    unsigned int byte_order_magic;
    unsigned short major_version;
    unsigned short minor_version;
    unsigned long long section_length;
    unsigned int options;
    unsigned int block_total_len_post;
} section_block_header_t;

typedef struct option_if_tsresol_t {
    unsigned short type;
    unsigned short length;
    unsigned char value;
} option_if_tsresol_t;

typedef struct interface_description_block_t {
    unsigned int block_type;
    unsigned int block_total_len_pre;
    unsigned short link_type;
    unsigned short reserved;
    unsigned int snap_len;
    option_if_tsresol_t if_tsresol;
    unsigned int block_total_len_post;
} interface_description_block_t;

typedef struct enhanced_packet_block_t {
    unsigned int block_type;
    unsigned int block_total_len_pre;
    unsigned int interface_id;
    unsigned int timestamp_high;
    unsigned int timestamp_low;
    unsigned int captured_len;
    unsigned int packet_len;
    unsigned int *data;
    unsigned int *options;
    unsigned int block_total_len_post;
} enhanced_packet_block_t;

// The overhead of the Enhanced Packet Block structure (everything but the data pointer)
#define PCAPNG_EPB_OVERHEAD_BYTES (sizeof(enhanced_packet_block_t) - sizeof(unsigned int * unsafe))

#ifdef __XC__
}
#endif

#endif // __PCAPNG_H__
