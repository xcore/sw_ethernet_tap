#ifndef __ETHERNET_TAP__
#define __ETHERNET_TAP__

/*
 * Open the relay on the Ethernet Tap to take down the link.
 * Note: this function takes 10ms to complete as that is the time the
 * relay takes to activate.
 */
void ethernet_tap_set_relay_open();

/*
 * Close the relay on the Ethernet Tap to bring the link back up.
 * Note: this function takes 10ms to complete as that is the time the
 * relay takes to activate.
 */
void ethernet_tap_set_relay_close();

#endif // __ETHERNET_TAP__
