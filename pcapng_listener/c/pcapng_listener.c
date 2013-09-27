/*
 * Note that the device and listener should be run with the same port and IP.
 * For example:
 *
 *  xrun --xscope-realtime --xscope-port 127.0.0.1:12346 ...
 *
 *  ./pcapng_listener 127.0.0.1 12346
 *
 */
#ifdef _WIN32
  #include <winsock.h>
  #pragma comment(lib, "Ws2_32.lib")

  // Provided by the inet_pton.c implementation locally
  int inet_pton(int af, const char *src, void *dst);
#else
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <errno.h>
  #include <arpa/inet.h>
#endif

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "pcapng.h"

#define DEBUG 0

// Different event types to register and handle
#define EVENT_DATA  0x2
#define EVENT_PRINT 0x8

// Need one byte for type, then 8 bytes of time stamp and 4 bytes of length
#define PRINT_EVENT_BYTES 13

// Data events have 16 bytes of overhead (event type, id, flag[2], length[4], timestamp[8])
#define DATA_EVENT_HEADER_BYTES 8
#define DATA_EVENT_BYTES 16

#define MAX_RECV_BYTES 16384

#define CAPTURE_LENGTH 64

#define EXTRACT_UINT(buf, pos) (buf[pos] | (buf[pos+1] << 8) | (buf[pos+2] << 16) | (buf[pos+3] << 24))

void emit_section_header_block(FILE *f)
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

void emit_interface_description_block(FILE *f)
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

FILE *g_log = NULL;
FILE *g_pcap_fptr = NULL;

void int_handler(int sig)
{
  fflush(g_log);
  fclose(g_log);
  fflush(g_pcap_fptr);
  fclose(g_pcap_fptr);
  printf("\nFinishing\n");
  exit(1);
}

void handle_socket(int sockfd)
{
  int total_bytes = 0;
  int num_remaining_bytes = 0;
  unsigned char recv_buffer[MAX_RECV_BYTES];
  int n = 0;

#ifdef _WIN32
  while ((n = recv(sockfd, &recv_buffer[num_remaining_bytes], sizeof(recv_buffer) - num_remaining_bytes, MSG_PARTIAL)) > 0) {
#else
  while ((n = read(sockfd, &recv_buffer[num_remaining_bytes], sizeof(recv_buffer) - num_remaining_bytes)) > 0) {
#endif
    int i;

    if (DEBUG)
      fprintf(g_log, ">> Received %d", n);

    n += num_remaining_bytes;
    num_remaining_bytes = 0;
    if (DEBUG) {
      for (i = 0; i < n; i++) {
        if ((i % 16) == 0)
          fprintf(g_log, "\n");
        fprintf(g_log, "%02x ", recv_buffer[i]);
      }
      fprintf(g_log, "\n");
    }

    for (i = 0; i < n; ) {
      // Indicate when a block of data has been handled by the fact that the pointer can move on
      int increment = 0;

      if (recv_buffer[i] == EVENT_PRINT) {
        unsigned int string_len = 0;

        // Need one byte for type, then 8 bytes of time stamp and 4 bytes of length
        if ((i + PRINT_EVENT_BYTES) <= n) {
          unsigned int string_len = EXTRACT_UINT(recv_buffer, i + 9);

          // Ensure the buffer won't overflow
          int string_start = i + PRINT_EVENT_BYTES;
          int string_end = i + PRINT_EVENT_BYTES + string_len;

          // Assertion has to be after variable declaration for Windows c89 compile
          assert(string_len < MAX_RECV_BYTES);

          if (string_end <= n) {
            // Ensure the string is null-terminated
            unsigned char tmp = recv_buffer[string_end];
            recv_buffer[string_end] = '\0';

            fwrite(&recv_buffer[string_start], sizeof(unsigned char), string_len, stdout);
            if (DEBUG)
              fprintf(g_log, "Found string length (%d) %02x '%s'\n", string_len, tmp, &recv_buffer[string_start]);

            recv_buffer[string_end] = tmp;

            increment = PRINT_EVENT_BYTES + string_len;
          }
        }

      } else if (recv_buffer[i] == EVENT_DATA) {
        if ((i + DATA_EVENT_HEADER_BYTES) <= n) {
          int packet_len = EXTRACT_UINT(recv_buffer, i + 4);

          if ((i + packet_len + DATA_EVENT_BYTES) <= n) {
            // Data starts after the message header
            int data_start = i + DATA_EVENT_HEADER_BYTES;

            // An entire packet has been received - write it to the file
            total_bytes += packet_len;

            fwrite(&recv_buffer[data_start], packet_len, 1, g_pcap_fptr);
            increment = packet_len + DATA_EVENT_BYTES;
          }
        }

      } else {
        printf("ERROR: Message format corrupted (received %u)\n", recv_buffer[0]);
        exit(1);
      }

      if (increment) {
        i += increment;

      } else {
        // Only part of the packet received - store rest for next iteration
        num_remaining_bytes = n - i;
        memmove(recv_buffer, &recv_buffer[i], num_remaining_bytes);

        if (DEBUG)
          fprintf(g_log, "%d remaining\n", num_remaining_bytes);

        break;
      }
    }
  }
}

int main(int argc, char *argv[])
{
  int sockfd = 0;
  int n = 0;
  unsigned char command_buffer[1];
  struct sockaddr_in serv_addr;
  char *end_pointer = NULL;
  int port = 0;

  if (DEBUG)
    g_log = fopen("run.log", "w");

  g_pcap_fptr = fopen("cap.pcapng", "wb");

  signal(SIGINT, int_handler);

  if (argc != 3) {
    printf("Usage: %s <ip of server> <port>\n", argv[0]);
    exit(1);
  }

#ifdef _WIN32
  {
    //Start up Winsock
    WSADATA wsadata;

    int error = WSAStartup(0x0202, &wsadata);
    if (error) {
      printf("ERROR: WSAStartup failed with '%d'\n", error);
      exit(1);
    }

    //Did we get the right Winsock version?
    if (wsadata.wVersion != 0x0202) {
      printf("ERROR: WSAStartup version incorrect '%x'\n", wsadata.wVersion);
      WSACleanup();
      exit(1);
    }
  }
#endif // _WIN32

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("ERROR: Could not create socket\n");
    exit(1);
  }

  memset(&serv_addr, 0, sizeof(serv_addr));

  // Parse the port parameter
  end_pointer = (char*)argv[2];
  port = strtol(argv[2], &end_pointer, 10);
  if (end_pointer == argv[2]) {
    printf("ERROR: Failed to parse port '%s'\n", argv[2]);
    exit(1);
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);

  if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0) {
    printf("ERROR: inet_pton error occured\n");
    exit(1);
  }

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("ERROR: Connect failed\n");
    exit(1);
  }

  emit_section_header_block(g_pcap_fptr);

  // Emit two interface descriptions as there are two on the tap
  emit_interface_description_block(g_pcap_fptr);
  emit_interface_description_block(g_pcap_fptr);

  // Send the command to request which event types to receive
  command_buffer[0] = EVENT_DATA | EVENT_PRINT;
  n = send(sockfd, command_buffer, 1, 0);
  if (n != 1) {
    printf("ERROR: Command send failed\n");
    exit(1);
  }

  printf("Connected\n");

  handle_socket(sockfd);

  return 0;
}

