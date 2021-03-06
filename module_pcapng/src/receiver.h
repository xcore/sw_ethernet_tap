#ifndef __RECEIVER_H__
#define __RECEIVER_H__

#include <xs1.h>

/*
 * A function to keep track of the top bits of a 64-bit counter
 */
void pcapng_timer_server(streaming chanend c_clients[num_clients], unsigned num_clients);

/*
 * Structure to keep all the port information for the RX interface
 */
typedef struct {
  unsigned id;
  clock clk_mii_rx;                 /**< MII RX Clock Block **/
  in port p_mii_rxclk;              /**< MII RX clock wire */
  in buffered port:32 p_mii_rxd;    /**< MII RX data wire */
  in port p_mii_rxdv;               /**< MII RX data valid wire */
} pcapng_mii_rx_t;

void pcapng_receiver(streaming chanend rx, pcapng_mii_rx_t &mii, streaming chanend c_time_server);

#endif // __RECEIVER_H__
