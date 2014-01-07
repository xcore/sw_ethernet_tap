/*
 * Note that the device and listener should be run with the same port and IP.
 * For example:
 *
 *  xrun --xscope-realtime --xscope-port 127.0.0.1:12346 ...
 *
 *  ./packet_analyser -s 127.0.0.1 -p 12346
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
#include "analysis_utils.h"
#include "packet_analyser.h"

const char *g_prompt = "";

void hook_data_received(int xscope_probe, void *data, int data_len)
{
  interface_state_t *state = (interface_state_t *)data;
  double mega_bits_per_second = (state->byte_snapshot * 8.0) / 1000000.0;

  const unsigned int preamble_bytes = 8;
  const unsigned int ifg_bytes = 96/8;
  const unsigned int used_bytes = state->byte_snapshot + (state->packet_snapshot * (preamble_bytes + ifg_bytes));
  const unsigned int used_bits = used_bytes * 8;
  double utilisation = (used_bits / 100000000.0) * 100.0;

  printf("| %7d | %8d | %6.2f | %6.2f %% |",
      state->packet_snapshot, state->byte_snapshot, mega_bits_per_second, utilisation);

  if (state->interface_id) {
    printf("\n");
    fflush(stdout);
  }
}

void hook_exiting()
{
  // Do nothing
}

void print_console_usage()
{
  printf("Supported commands:\n");
  printf("  h|?     : print this help message\n");
  printf("  c       : close the relay (connect)\n");
  printf("  o       : open the relay (disconnect)\n");
  printf("  q       : quit\n");
}

#define LINE_LENGTH 1024

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

    for (i = 0; (i < LINE_LENGTH) && ((c = getchar()) != EOF) && (c != '\n'); i++)
      buffer[i] = tolower(c);
    buffer[i] = '\0';

    switch (buffer[0]) {
      case 'q':
        print_and_exit("Done\n");
        break;

      case 'c': {
        tester_command_t cmd = PACKET_ANALYSER_SET_RELAY_CLOSE;
        xscope_ep_request_upload(sockfd, 4, (unsigned char *)&cmd);
        break;
      }

      case 'o': {
        tester_command_t cmd = PACKET_ANALYSER_SET_RELAY_OPEN;
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
  if (optind < argc)
    err++;

  if (err)
    usage(argv);

  sockfds[0] = initialise_socket(server_ip, port_str);

  printf("|                 UP                     ||                  DOWN                  |\n");
  printf("| Packets | Bytes    | Mb/s   | %% util   || Packets | Bytes    | Mb/s   | %% util   |\n");

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

