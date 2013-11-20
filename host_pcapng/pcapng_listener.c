/*
 * Note that the device and listener should be run with the same port and IP.
 * For example:
 *
 *  xrun --xscope-realtime --xscope-port 127.0.0.1:12346 ...
 *
 *  ./pcapng_listener -s 127.0.0.1 -p 12346
 *
 */
#include "xscope_host_shared.h"

#include "pcapng.h"
#include "pcap.h"

#define DEFAULT_FILE "cap.pcapng"

FILE *g_pcap_fptr = NULL;

// Indicate whether the output should be pcap or pcapng
int g_libpcap_mode = 0;

void hook_data_received(int xscope_probe, void *data, int data_len)
{
  if (g_libpcap_mode) {
    // Convert the pacpng data from the target to libpcap format
    enhanced_packet_block_t *ehb = (enhanced_packet_block_t *) data;

    // Time resolution in pcapng is 10ns
    uint64_t packet_time = (((uint64_t)ehb->timestamp_high << 32) | ehb->timestamp_low) / 100;
    uint32_t ts_sec = packet_time / 1000000;
    uint32_t ts_usec = packet_time % 1000000;

    pcaprec_hdr_t header = { ts_sec, ts_usec, ehb->captured_len, ehb->packet_len };
    fwrite(&header, sizeof(header), 1, g_pcap_fptr);
    fwrite(&ehb->data, ehb->captured_len, 1, g_pcap_fptr);
    fflush(g_pcap_fptr);
  } else {
    // Emit the pcapng data
    fwrite(data, data_len, 1, g_pcap_fptr);
  }
}

void hook_exiting()
{
  fflush(g_pcap_fptr);
  fclose(g_pcap_fptr);
}

void emit_pcap_header(FILE *f)
{
  pcap_hdr_t header = {
    0xA1B2C3D4,             // Byte-Order Magic
    0x2,                    // Major Version
    0x4,                    // Minor Version
    0x0,                    // Time zone (GMT)
    0x0,                    // Accuracy - simply set 0
    CAPTURE_LENGTH,         // Snaplength
    DATA_LINK_ETHERNET,     // Data link type
  };
  fwrite(&header, sizeof(header), 1, f);
}

void emit_pcapng_section_header_block(FILE *f)
{
  section_block_header_t header = {
    0x0A0D0D0A,             // Block Type
    32,                     // Block Total Length
    0x1A2B3C4D,             // Byte-Order Magic
    0x1,                    // Major Version
    0x0,                    // Minor Version
    0xffffffffffffffffull,  // Section Length
    0x0,                    // Options
    32                      // Block Total Length
  };
  fwrite(&header, sizeof(header), 1, f);
}

void emit_pcapng_interface_description_block(FILE *f)
{
  interface_description_block_t iface = {
    0x1,                                    // Block Type
    sizeof(interface_description_block_t),  // Block Total Length
    0x1,                                    // LinkType
    0x0,                                    // Reserved
    CAPTURE_LENGTH,                         // SnapLen
    // Options
    { 0x09, 0x01, 0x08 },                       // if_tsresol (10^-8)
    sizeof(interface_description_block_t)   // Block Total Length
  };
  fwrite(&iface, sizeof(iface), 1, f);
}

void usage(char *argv[])
{
  printf("Usage: %s [-s server_ip] [-p port] [-l] [file]\n", argv[0]);
  printf("  -s server_ip :   The IP address of the xscope server (default %s)\n", DEFAULT_SERVER_IP);
  printf("  -p port      :   The port of the xscope server (default %s)\n", DEFAULT_PORT);
  printf("  -l           :   Emit libpcap format instead of pcapng\n");
  printf("  file         :   File name packets are written to (default '%s')\n", DEFAULT_FILE);
  exit(1);
}

int main(int argc, char *argv[])
{
  char *server_ip = DEFAULT_SERVER_IP;
  char *port_str = DEFAULT_PORT;
  char *filename = DEFAULT_FILE;
  int err = 0;
  int sockfd = 0;
  int c = 0;

  while ((c = getopt(argc, argv, "ls:p:")) != -1) {
    switch (c) {
      case 's':
        server_ip = optarg;
        break;
      case 'p':
        port_str = optarg;
        break;
      case 'l':
        g_libpcap_mode = 1;
        break;
      case ':': /* -f or -o without operand */
        fprintf(stderr, "Option -%c requires an operand\n", optopt);
        err++;
        break;
      case '?':
        fprintf(stderr, "Unrecognized option: '-%c'\n", optopt);
        err++;
    }
  }
  for ( ; optind < argc; optind++) {
    if (filename != DEFAULT_FILE)
      err++;
    filename = argv[optind];
    break;
  }

  if (err)
    usage(argv);

  sockfd = initialise_common(server_ip, port_str);
  g_pcap_fptr = fopen(filename, "wb");

  if (g_libpcap_mode) {
    // Emit libpcap common header
    emit_pcap_header(g_pcap_fptr);

  } else {
    // Emit common header and two interface descriptions as there are two on the tap
    emit_pcapng_section_header_block(g_pcap_fptr);
    emit_pcapng_interface_description_block(g_pcap_fptr);
    emit_pcapng_interface_description_block(g_pcap_fptr);
  }
  fflush(g_pcap_fptr);

  handle_socket(sockfd);

  return 0;
}

