/*
 * Note that the device and listener should be run with the same port and IP.
 * For example:
 *
 *  xrun --xscope-realtime --xscope-port 127.0.0.1:12346 ...
 *
 *  ./pcapng_listener -s 127.0.0.1 -p 12346
 *
 */
/*
 * Includes for thread support
 */
#ifdef _WIN32
  #include <winsock.h>
#else
  #include <pthread.h>
#endif

#include "xscope_host_shared.h"
#include "avb_tester.h"

#define DEFAULT_FILE "cap.pcapng"

const char *g_prompt = " > ";

// Indicate whether the output should be pcap or pcapng
int g_libpcap_mode = 0;

void hook_registration_received(int sockfd, int xscope_probe, char *name)
{
  // Do nothing
}

void hook_data_received(int xscope_probe, void *data, int data_len)
{
  // Do nothing
}

void hook_exiting()
{
}

void print_console_usage()
{
  printf("Supported commands:\n");
  printf("  h|?     : print this help message\n");
  printf("  e <o|n> : tell app to expect (o)versubscribed or (n)ormal traffic\n");
  printf("  d <e|d> : tell app to (e)nable or (d)isable debug output\n");
  printf("  c       : close the relay (connect)\n");
  printf("  o       : open the relay (disconnect)\n");
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

    switch (buffer[0]) {
      case 'q':
        print_and_exit("Done\n");
        break;

      case 'e': {
        tester_command_t cmd = AVB_TESTER_EXPECT_NORMAL;
        if (get_next_char(&buffer[1]) == 'o')
          cmd = AVB_TESTER_EXPECT_OVERSUBSCRIBED;
        xscope_ep_request_upload(sockfd, 4, (unsigned char *)&cmd);
        break;
      }

      case 'd': {
        tester_command_t cmd = AVB_TESTER_PRINT_DEBUG_DISABLE;
        if (get_next_char(&buffer[1]) == 'e')
          cmd = AVB_TESTER_PRINT_DEBUG_ENABLE;
        xscope_ep_request_upload(sockfd, 4, (unsigned char *)&cmd);
        break;
      }

      case 'c': {
        tester_command_t cmd = AVB_TESTER_SET_RELAY_CLOSE;
        xscope_ep_request_upload(sockfd, 4, (unsigned char *)&cmd);
        break;
      }

      case 'o': {
        tester_command_t cmd = AVB_TESTER_SET_RELAY_OPEN;
        xscope_ep_request_upload(sockfd, 4, (unsigned char *)&cmd);
        break;
      }

      case 'h':
      case '?':
        print_console_usage();
        break;

      default:
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

void usage(char *argv[])
{
  printf("Usage: %s [-s server_ip] [-p port]\n", argv[0]);
  printf("  -s server_ip :   The IP address of the xscope server (default %s)\n", DEFAULT_SERVER_IP);
  printf("  -p port      :   The port of the xscope server (default %s)\n", DEFAULT_PORT);
  exit(1);
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
  HANDLE thread;
#else
  pthread_t tid;
#endif

  char *server_ip = DEFAULT_SERVER_IP;
  char *port_str = DEFAULT_PORT;
  int err = 0;
  int sockfds[1] = {0};
  int c = 0;

  while ((c = getopt(argc, argv, "s:p:")) != -1) {
    switch (c) {
      case 's':
        server_ip = optarg;
        break;
      case 'p':
        port_str = optarg;
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
  
  if (err)
    usage(argv);

  sockfds[0] = initialise_socket(server_ip, port_str);

  // Now start the console
#ifdef _WIN32
  thread = CreateThread(NULL, 0, console_thread, &sockfds[0], 0, NULL);
  if (thread == NULL)
    print_and_exit("ERROR: Failed to create console thread\n");
#else
  err = pthread_create(&tid, NULL, &console_thread, &sockfds[0]);
  if (err != 0)
    print_and_exit("ERROR: Failed to create console thread\n");
#endif

  handle_sockets(sockfds, 1);

  return 0;
}

