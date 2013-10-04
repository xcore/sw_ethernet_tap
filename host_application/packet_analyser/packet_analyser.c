/*
 * Note that the device and listener should be run with the same port and IP.
 * For example:
 *
 *  xrun --xscope-realtime --xscope-port 127.0.0.1:12346 ...
 *
 *  ./packet_analyser 127.0.0.1 12346
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

int main(int argc, char *argv[])
{
  int sockfd = initialise_common(argc, argv);

  printf("|                 UP                     ||                  DOWN                  |\n");
  printf("| Packets | Bytes    | Mb/s   | %% util   || Packets | Bytes    | Mb/s   | %% util   |\n");

  handle_socket(sockfd);
  return 0;
}

