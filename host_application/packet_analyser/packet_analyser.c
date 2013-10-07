/*
 * Note that the device and listener should be run with the same port and IP.
 * For example:
 *
 *  xrun --xscope-realtime --xscope-port 127.0.0.1:12346 ...
 *
 *  ./packet_analyser -s 127.0.0.1 -p 12346
 *
 */
#include "shared.h"
#include "analysis_utils.h"

// Need to define this as NULL to indicate that there is no console being used
const char *g_prompt = NULL;

void hook_data_received(void *data, int data_len)
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

void usage(char *argv[])
{
  printf("Usage: %s [-s server_ip] [-p port]\n", argv[0]);
  printf("  -s server_ip :   The IP address of the xscope server (default %s)\n", DEFAULT_SERVER_IP);
  printf("  -p port      :   The port of the xscope server (default %s)\n", DEFAULT_PORT);
  exit(1);
}

int main(int argc, char *argv[])
{
  char *server_ip = DEFAULT_SERVER_IP;
  char *port_str = DEFAULT_PORT;
  int err = 0;
  int sockfd = 0;
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

  sockfd = initialise_common(server_ip, port_str);

  printf("|                 UP                     ||                  DOWN                  |\n");
  printf("| Packets | Bytes    | Mb/s   | %% util   || Packets | Bytes    | Mb/s   | %% util   |\n");

  handle_socket(sockfd);
  return 0;
}

