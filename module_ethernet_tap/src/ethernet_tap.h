#ifndef __ETHERNET_TAP__
#define __ETHERNET_TAP__

/**
 * \brief   The interface between the xscope receiver and the relay control
 */
interface ethernet_tap_relay_control_if {
  void set_relay_open();
  void set_relay_close();
};

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

/**
 * \brief   A core to control the ethernet tap relay
 *
 * \param   i_relay_control           Interface for controlling the relay
 */
void relay_control(server interface ethernet_tap_relay_control_if i_relay_control);

#endif // __ETHERNET_TAP__
