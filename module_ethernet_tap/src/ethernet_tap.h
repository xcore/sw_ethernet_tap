#ifndef __ETHERNET_TAP__
#define __ETHERNET_TAP__

#define TEN_MILLISEC 1000000

/**
 * \brief   The interface between the xscope receiver and the relay control
 */
interface ethernet_tap_relay_control_if {
  void set_relay_open();
  void set_relay_close();
};

/*
 * \brief   Set the relay control pins to idle.
 */
void ethernet_tap_set_control_idle();

/*
 * \brief   Drive the relay control pins to open the relay. After 10ms
 *          ethernet_tap_set_control_idle() should be called.
 */
void ethernet_tap_set_relay_open();

/*
 * \brief   Drive the relay control pins to close the relay. After 10ms
 *          ethernet_tap_set_control_idle() should be called.
 */
void ethernet_tap_set_relay_close();

/**
 * \brief   A core to control the ethernet tap relay
 *
 * \param   i_relay_control           Interface for controlling the relay
 */
[[combinable]]
void relay_control(server interface ethernet_tap_relay_control_if i_relay_control);

#endif // __ETHERNET_TAP__
