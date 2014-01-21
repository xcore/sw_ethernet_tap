#include <xs1.h>
#include <platform.h>

#include "ethernet_tap.h"
#include "debug_print.h"

on tile[1] : out port port_ethernet_tap_relay0 = XS1_PORT_1I;
on tile[1] : out port port_ethernet_tap_relay1 = XS1_PORT_1L;

void ethernet_tap_set_control_idle()
{
  port_ethernet_tap_relay0 <: 0;
  port_ethernet_tap_relay1 <: 0;
}

void ethernet_tap_set_relay_open()
{
  port_ethernet_tap_relay0 <: 1;
}

void ethernet_tap_set_relay_close()
{
  port_ethernet_tap_relay1 <: 1;
}

[[combinable]]
void relay_control(server interface ethernet_tap_relay_control_if i_relay_control)
{
  timer t;
  int time;
  int active = 0;
  while (1) {
    select {
      case i_relay_control.set_relay_open() :
        ethernet_tap_set_relay_open();
        t :> time;
        active = 1;
        break;

      case i_relay_control.set_relay_close() :
        ethernet_tap_set_relay_close();
        t :> time;
        active = 1;
        break;

      case active => t when timerafter(time + TEN_MILLISEC) :> void :
        ethernet_tap_set_control_idle();
        active = 0;
        break;
    }
  }
}
