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
  #include <pthread.h>
#endif

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "pcapng.h"
#include "avb_tester.h"

#define DEBUG 1

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
const char *g_prompt = " > ";

void int_handler(int sig)
{
  fflush(g_log);
  fclose(g_log);
  fflush(g_pcap_fptr);
  fclose(g_pcap_fptr);
  printf("\nFinishing\n");
  exit(1);
}

void error(const char* format, ...)
{
  va_list argptr;
  va_start(argptr, format);
  vfprintf(stderr, format, argptr);
  va_end(argptr);
  exit(1);
}

unsigned char tmp[] = "Test0";

int xscope_ep_upload_pending = 0;

/*
 * Function that sends data to the device over the socket. Puts the data into
 * a message of the correct format and sends it to the socket. It expects
 * there to be only one outstanding message at a time. This is not an xscope
 * limitation, just one for simplicity.
 */
int xscope_ep_request_upload(int sockfd, unsigned int length,
    const unsigned char *data)
{
  char request = XSCOPE_SOCKET_MSG_EVENT_TARGET_DATA;
  char *requestBuffer = (char *)malloc(sizeof(char)+sizeof(int)+length);
  int requestBufIndex = 0;
  int n = 0;

  if (xscope_ep_upload_pending == 1)
    return XSCOPE_EP_FAILURE;

  requestBuffer[requestBufIndex] = request;
  requestBufIndex += 1;
  *(unsigned int *)&requestBuffer[requestBufIndex] = length;
  requestBufIndex += 4;
  memcpy(&requestBuffer[requestBufIndex], data, length);
  requestBufIndex += length;

  n = send(sockfd, requestBuffer, requestBufIndex, 0);
  if (n != requestBufIndex)
    error("ERROR: Command send failed\n");

  xscope_ep_upload_pending = 1;
  free(requestBuffer);

  return XSCOPE_EP_SUCCESS;
}

/*
 * Function to handle all data being received on the socket. It handles the
 * fact that full messages may not be received together and therefore needs
 * to keep the remainder of any message that hasn't been processed yet.
 */
void handle_socket(int sockfd)
{
  int total_bytes = 0;
  int num_remaining_bytes = 0;
  unsigned char recv_buffer[MAX_RECV_BYTES];
  int n = 0;

  // Keep track of whether a message should be printed at the start of the line
  // and when the prompt needs to be printed
  int new_line = 1;

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

      if (recv_buffer[i] == XSCOPE_SOCKET_MSG_EVENT_PRINT) {
        // Data to print to the screen has been received
        unsigned int string_len = 0;

        // Need one byte for type, then 8 bytes of time stamp and 4 bytes of length
        if ((i + PRINT_EVENT_BYTES) <= n) {
          unsigned int string_len = EXTRACT_UINT(recv_buffer, i + 9);

          int string_start = i + PRINT_EVENT_BYTES;
          int string_end = i + PRINT_EVENT_BYTES + string_len;

          // Ensure the buffer won't overflow (has to be after variable
          // declaration for Windows c89 compile)
          assert(string_len < MAX_RECV_BYTES);

          if (string_end <= n) {
            // Ensure the string is null-terminated - but remember the data byte
            // in order to be able to restore it.
            unsigned char tmp = recv_buffer[string_end];
            recv_buffer[string_end] = '\0';

            if (new_line) {
              // When starting to print a message, emit a carriage return in order
              // to overwrite the prompt
              printf("\r");
              new_line = 0;
            }

            fwrite(&recv_buffer[string_start], sizeof(unsigned char), string_len, stdout);

            if (recv_buffer[string_end - 1] == '\n') {
              // When a string ends with a newline then print the prompt again
              printf("%s", g_prompt);

              // Because there is no newline character we need to explictly flush
              fflush(stdout);
              new_line = 1;
            }

            // Restore the end character
            recv_buffer[string_end] = tmp;

            increment = PRINT_EVENT_BYTES + string_len;
          }
        }

      } else if (recv_buffer[i] == XSCOPE_SOCKET_MSG_EVENT_DATA) {
        // Data has been received, put it into the pcap file
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

      } else if (recv_buffer[i] == XSCOPE_SOCKET_MSG_EVENT_TARGET_DATA) {
        // The target acknowledges that it has received the message sent
        if ((i + TARGET_DATA_EVENT_BYTES) <= n) {
          xscope_ep_upload_pending = 0;
          increment = TARGET_DATA_EVENT_BYTES;
        }

      } else {
        error("ERROR: Message format corrupted (received %u)\n", recv_buffer[0]);
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

void print_console_usage()
{
  printf("Supported commands:\n");
  printf("  h|?     : print this help message\n");
  printf("  e <o|n> : tell app to expect (o)versubscribed or (n)ormal traffic\n");
  printf("  x <e|d> : tell app to (e)nable or (d)isable xscope packet dumping\n");
  printf("  q       : quit\n");
}

#define LINE_LENGTH 1024

char get_next_char(char *buffer)
{
  char *ptr = buffer;
  while (*ptr && isspace(*ptr))
    ptr++;
  return *ptr;
}

/*
 * A separate thread to handle user commands to control the target.
 */
#ifdef _WIN32
DWORD WINAPI console_thread(void *arg)
#else
void *console_thread(void *arg)
#endif
{
  int sockfd = *(int *)arg;
  char buffer[LINE_LENGTH + 1];
  do {
    int i = 0;
    int c = 0;

    printf("%s", g_prompt);
    for (i = 0; (i < LINE_LENGTH) && ((c = getchar()) != EOF) && (c != '\n'); i++)
      buffer[i] = tolower(c);
    buffer[i] = '\0';

    if (buffer[0] == 'q') {
      error("Done\n");

    } else if (buffer[0] == 'e') {
      tester_command_t cmd = AVB_TESTER_EXPECT_NORMAL;
      if (get_next_char(&buffer[1]) == 'o')
        cmd = AVB_TESTER_EXPECT_OVERSUBSCRIBED;
      xscope_ep_request_upload(sockfd, 4, (char *)&cmd);

    } else if (buffer[0] == 'x') {
      tester_command_t cmd = AVB_TESTER_XSCOPE_PACKETS_DISABLE;
      if (get_next_char(&buffer[1]) == 'e')
        cmd = AVB_TESTER_XSCOPE_PACKETS_ENABLE;
      xscope_ep_request_upload(sockfd, 4, (char *)&cmd);

    } else if ((buffer[0] == 'h') || (buffer[0] == '?')) {
      print_console_usage();

    } else {
      printf("Unrecognised command '%s'\n", buffer);
      print_console_usage();
    }
  } while (1);

#ifdef _WIN32
  return 0;
#else
  return NULL;
#endif
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
  HANDLE thread;
#else
  pthread_t tid;
#endif
  int err = 0;
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

  if (argc != 3)
    error("Usage: %s <ip of server> <port>\n", argv[0]);

#ifdef _WIN32
  {
    //Start up Winsock
    WSADATA wsadata;
    int retval = WSAStartup(0x0202, &wsadata);
    if (retval)
      error("ERROR: WSAStartup failed with '%d'\n", retval);

    //Did we get the right Winsock version?
    if (wsadata.wVersion != 0x0202) {
      WSACleanup();
      error("ERROR: WSAStartup version incorrect '%x'\n", wsadata.wVersion);
    }
  }
#endif // _WIN32

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    error("ERROR: Could not create socket\n");

  memset(&serv_addr, 0, sizeof(serv_addr));

  // Parse the port parameter
  end_pointer = (char*)argv[2];
  port = strtol(argv[2], &end_pointer, 10);
  if (end_pointer == argv[2])
    error("ERROR: Failed to parse port\n");

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);

  if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0)
    error("ERROR: inet_pton error occured\n");

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    error("ERROR: Connect failed\n");

  emit_section_header_block(g_pcap_fptr);

  // Emit two interface descriptions as there are two on the tap
  emit_interface_description_block(g_pcap_fptr);
  emit_interface_description_block(g_pcap_fptr);

  // Send the command to request which event types to receive
  command_buffer[0] = XSCOPE_SOCKET_MSG_EVENT_DATA | XSCOPE_SOCKET_MSG_EVENT_PRINT;
  //command_buffer[0] = XSCOPE_SOCKET_MSG_EVENT_DATA;
  n = send(sockfd, command_buffer, 1, 0);
  if (n != 1)
    error("ERROR: Command send failed\n");

  printf("Connected\n");

  // Now start the console
#ifdef _WIN32
  thread = CreateThread(NULL, 0, console_thread, &sockfd, 0, NULL);
  if (thread == NULL)
    error("ERROR: Failed to create console thread\n");
#else
  err = pthread_create(&tid, NULL, &console_thread, &sockfd);
  if (err != 0)
    error("ERROR: Failed to create console thread\n");
#endif

  handle_socket(sockfd);

  return 0;
}

