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
#include "avb_tester.h"
#include "analysis_utils.h"

// Need to define this as NULL to indicate that there is no console being used
const char *g_prompt = NULL;

void hook_data_received(void *data, int data_len)
{
  interface_state_t *state = (interface_state_t *)data;
  double mega_bits_per_second = (state->byte_snapshot * 8.0) / 1000000.0;

  printf("%s %6d packets %10d bytes %3.2f Mb/s", state->interface_id ? " | DOWN" : "UP",
      state->packet_snapshot, state->byte_snapshot, mega_bits_per_second);

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
  handle_socket(sockfd);
  return 0;
}

