#include "shared.h"

#define DEBUG 0
#define MAX_NUM_CONNECT_RETRIES 20

FILE *g_log = NULL;

/*
 * HOOKS: The application needs to implement the following hooks
 */

// Called whenever data is received from the target
void hook_data_received(int xscope_probe, void *data, int data_len);

// Called whenever the application is existing
void hook_exiting();

// The application needs to define the prompt if it is going to use
// a console application. If it is NULL then it is assumed there is
// no console on the host.
extern const char *g_prompt;

int initialise_common(char *ip_addr_str, char *port_str)
{
  int sockfd = 0;
  int n = 0;
  unsigned char command_buffer[1];
  struct sockaddr_in serv_addr;
  char *end_pointer = NULL;
  int port = 0;
  int connect_retries = 0;

  if (DEBUG)
    g_log = fopen("run.log", "w");

  signal(SIGINT, interrupt_handler);

#ifdef _WIN32
  {
    //Start up Winsock
    WSADATA wsadata;
    int retval = WSAStartup(0x0202, &wsadata);
    if (retval)
      print_and_exit("ERROR: WSAStartup failed with '%d'\n", retval);

    //Did we get the right Winsock version?
    if (wsadata.wVersion != 0x0202) {
      WSACleanup();
      print_and_exit("ERROR: WSAStartup version incorrect '%x'\n", wsadata.wVersion);
    }
  }
#endif // _WIN32

  // Need the fflush because there is no newline in the print
  printf("Connecting"); fflush(stdout);
  while (1) {
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
      print_and_exit("ERROR: Could not create socket\n");

    memset(&serv_addr, 0, sizeof(serv_addr));

    // Parse the port parameter
    end_pointer = (char*)port_str;
    port = strtol(port_str, &end_pointer, 10);
    if (end_pointer == port_str)
      print_and_exit("ERROR: Failed to parse port\n");

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip_addr_str, &serv_addr.sin_addr) <= 0)
      print_and_exit("ERROR: inet_pton error occured\n");

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
      close(sockfd);

      if (connect_retries < MAX_NUM_CONNECT_RETRIES) {
        // Need the fflush because there is no newline in the print
        printf("."); fflush(stdout);
#ifdef _WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
        connect_retries++;
      } else {
        print_and_exit("\nERROR: Connect failed\n");
      }
    } else {
      break;
    }
  }

  // Send the command to request which event types to receive
  command_buffer[0] = XSCOPE_SOCKET_MSG_EVENT_DATA | XSCOPE_SOCKET_MSG_EVENT_PRINT;
  n = send(sockfd, command_buffer, 1, 0);
  if (n != 1)
    print_and_exit("\nERROR: Command send failed\n");

  printf(" - connected\n");

  return sockfd;
}

void interrupt_handler(int sig)
{
  hook_exiting();

  if (DEBUG) {
    fflush(g_log);
    fclose(g_log);
  }

  printf("\nFinishing\n");
  exit(1);
}

void print_and_exit(const char* format, ...)
{
  va_list argptr;
  va_start(argptr, format);
  vfprintf(stderr, format, argptr);
  va_end(argptr);
  exit(1);
}

int xscope_ep_upload_pending = 0;

int xscope_ep_request_upload(int sockfd, unsigned int length, const unsigned char *data)
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
    print_and_exit("ERROR: Command send failed\n");

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

            if (new_line && (g_prompt != NULL)) {
              // When starting to print a message, emit a carriage return in order
              // to overwrite the prompt
              printf("\r");
              new_line = 0;
            }

            fwrite(&recv_buffer[string_start], sizeof(unsigned char), string_len, stdout);

            if (recv_buffer[string_end - 1] == '\n') {
              // When a string ends with a newline then print the prompt again
              if (g_prompt != NULL)
                printf("%s", g_prompt);

              new_line = 1;
            }

            // Because there is no newline character at the end of the prompt and there
            // may be none at the end of the string then we need to flush explicitly
            fflush(stdout);

            // Restore the end character
            recv_buffer[string_end] = tmp;

            increment = PRINT_EVENT_BYTES + string_len;
          }
        }

      } else if (recv_buffer[i] == XSCOPE_SOCKET_MSG_EVENT_DATA) {
        // Data has been received, put it into the pcap file
        if ((i + DATA_EVENT_HEADER_BYTES) <= n) {
          int xscope_probe = recv_buffer[i+1];
          int packet_len = EXTRACT_UINT(recv_buffer, i + 4);

          // Fixed-length data packets are encoded with a length of 0
          // but actually carry 8 bytes of data
          if (packet_len == 0)
            packet_len = 8;

          if ((i + packet_len + DATA_EVENT_BYTES) <= n) {
            // Data starts after the message header
            int data_start = i + DATA_EVENT_HEADER_BYTES;

            // An entire packet has been received - write it to the file
            total_bytes += packet_len;

            hook_data_received(xscope_probe, &recv_buffer[data_start], packet_len);
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
        print_and_exit("ERROR: Message format corrupted (received %u)\n", recv_buffer[i]);
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

