/**
 * An analysis application to track AVB audio streams and monitor packet rates.
 * The host can determine whether the stream is expected to be oversubscribed
 * or not.
 */
#include <platform.h>
#include <xscope.h>
#include <stdint.h>

#include "receiver.h"
#include "debug_print.h"
#include "analysis_utils.h"
#include "receiver_tile.h"
#include "analysis_tile.h"

#define ANALYSIS_TILE 0
#define RECEIVER_TILE 1

// Circle slot
on tile[1]: pcapng_mii_rx_t mii2 = {
  1,
  XS1_CLKBLK_3,
  XS1_PORT_1B,
  XS1_PORT_4A,
  XS1_PORT_1C,
};

// Square slot
on tile[1]: pcapng_mii_rx_t mii1 = {
  0,
  XS1_CLKBLK_4,
  XS1_PORT_1J,
  XS1_PORT_4E,
  XS1_PORT_1K,
};

void xscope_user_init()
{
  xscope_register(1, XSCOPE_CONTINUOUS, "Packet Data", XSCOPE_UINT, "Value");
  xscope_config_io(XSCOPE_IO_BASIC);
}

/**
 * \brief   A core that listens to data being sent from the host and
 *          informs the analysis engine of any changes
 */
void xscope_listener(client interface analysis_config i_checker_config)
{
  // The maximum read size is 256 bytes
  unsigned int buffer[256/4];

  while (1) {
    unsigned int num_read = xscope_upload_bytes(-1, (unsigned char *)&buffer[0]);

    if (num_read == 4) {
      // Expecting a word from the host which indicates the command
      unsigned int cmd = buffer[0];
      switch (cmd) {
        default:
          debug_printf("Unrecognised command '%d' received from host\n", cmd);
          break;
      }

    } else if (num_read != 0) {
      debug_printf("ERROR: Received '%d' bytes\n", num_read);
    }
  }
}

enum {
  TIMER_CLIENT0 = 0,
  TIMER_CLIENT1,
  NUM_TIMER_CLIENTS
} timer_clients;

int main()
{
  chan c_inter_tile;
  par {
    on tile[ANALYSIS_TILE]: {
      chan c_receiver_to_control;
      chan c_control_to_analysis;
      interface analysis_config i_checker_config;

      analyse_init();
      par {
        buffer_receiver(c_inter_tile, c_receiver_to_control);
        analysis_control(c_receiver_to_control, c_control_to_analysis);
        analyser(c_control_to_analysis);
        periodic_checks(i_checker_config);
        xscope_listener(i_checker_config);
      }
    }

    on tile[RECEIVER_TILE] : {
      chan c_mii1;
      chan c_mii2;
      chan c_control_to_sender;
      interface pcapng_timer_interface i_tmr[NUM_TIMER_CLIENTS];

      par {
        buffer_sender(c_control_to_sender, c_inter_tile);
        receiver_control(c_mii1, c_mii2, c_control_to_sender);
        pcapng_receiver(c_mii1, mii1, i_tmr[TIMER_CLIENT0]);
        pcapng_receiver(c_mii2, mii2, i_tmr[TIMER_CLIENT1]);
        pcapng_timer_server(i_tmr, NUM_TIMER_CLIENTS);
      }
    }
  }
  return 0;
}

