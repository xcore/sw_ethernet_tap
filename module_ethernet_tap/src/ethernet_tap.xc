#include <xs1.h>
#include <platform.h>

#include "ethernet_tap.h"
#include "debug_print.h"

on tile[1] : out port port_ethernet_tap_relay0 = XS1_PORT_1I;
on tile[1] : out port port_ethernet_tap_relay1 = XS1_PORT_1L;

#define TEN_MILLISEC 1000000
void ethernet_tap_set_relay_open()
{
  timer t;
  int time;

  port_ethernet_tap_relay0 <: 0;
  port_ethernet_tap_relay1 <: 0;

  port_ethernet_tap_relay0 <: 1;
  t :> time;
  t when timerafter(time + TEN_MILLISEC) :> time;
  port_ethernet_tap_relay0 <: 0;
}

void ethernet_tap_set_relay_close()
{
  timer t;
  int time;

  port_ethernet_tap_relay0 <: 0;
  port_ethernet_tap_relay1 <: 0;

  port_ethernet_tap_relay1 <: 1;
  t :> time;
  t when timerafter(time + TEN_MILLISEC) :> time;
  port_ethernet_tap_relay1 <: 0;
}

