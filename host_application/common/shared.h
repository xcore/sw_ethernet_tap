#ifndef __SHARED_H__
#define __SHARED_H__

/*
 * The required includes for any host application.
 */
#ifdef _WIN32
  #include <winsock.h>
  #pragma comment(lib, "Ws2_32.lib")

  // Provided by the inet_pton.c implementation locally
  int inet_pton(int af, const char *src, void *dst);

  // Locally provided getopt.h
  #include "getopt.h"

  typedef unsigned __int8  uint8_t;
  typedef unsigned __int16 uint16_t;
  typedef unsigned __int32 uint32_t;
  typedef unsigned __int64 uint64_t;

  typedef __int8  int8_t;
  typedef __int16 int16_t;
  typedef __int32 int32_t;
  typedef __int64 int64_t;

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
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "pcapng.h"
#include "pcap.h"

#define XSCOPE_EP_SUCCESS 0
#define XSCOPE_EP_FAILURE 1

// Different event types to register and handle
#define XSCOPE_SOCKET_MSG_EVENT_DATA  0x2
#define XSCOPE_SOCKET_MSG_EVENT_TARGET_DATA 4
#define XSCOPE_SOCKET_MSG_EVENT_PRINT 0x8

// Need one byte for type, then 8 bytes of time stamp and 4 bytes of length
#define PRINT_EVENT_BYTES 13

// Data events have 16 bytes of overhead (event type, id, flag[2], length[4], timestamp[8])
#define DATA_EVENT_HEADER_BYTES 8
#define DATA_EVENT_BYTES 16

// The target completion message is the event type + data[4]
#define TARGET_DATA_EVENT_BYTES 5

#define MAX_RECV_BYTES 16384

#define CAPTURE_LENGTH 64

#define EXTRACT_UINT(buf, pos) (buf[pos] | (buf[pos+1] << 8) | (buf[pos+2] << 16) | (buf[pos+3] << 24))

#define DEFAULT_SERVER_IP "127.0.0.1"
#define DEFAULT_PORT "12346"

#ifdef __XC__
extern "C" {
#endif

int initialise_common(char *ip_addr_str, char *port_str);
void interrupt_handler(int sig);
void print_and_exit(const char* format, ...);

/*
 * Function that sends data to the device over the socket. Puts the data into
 * a message of the correct format and sends it to the socket. It expects
 * there to be only one outstanding message at a time. This is not an xscope
 * limitation, just one for simplicity.
 */
int xscope_ep_request_upload(int sockfd, unsigned int length, const unsigned char *data);

void handle_socket(int sockfd);

void emit_pcap_header(FILE *f);
void emit_pcapng_section_header_block(FILE *f);
void emit_pcapng_interface_description_block(FILE *f);

#ifdef __XC__
}
#endif

#endif // __SHARED_H__
