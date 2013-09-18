#include <platform.h>
#include <xscope.h>
#include <stdint.h>
#include <print.h>
#include <xclib.h>

#include "receiver.h"
#include "pcapng.h"
#include "pcapng_conf.h"

static void init_mii_rx(pcapng_mii_rx_t &m)
{
  set_port_use_on(m.p_mii_rxclk);
  m.p_mii_rxclk :> int x;
  set_port_use_on(m.p_mii_rxd);
  set_port_use_on(m.p_mii_rxdv);
  set_pad_delay(m.p_mii_rxclk, PAD_DELAY_RECEIVE);

  set_port_strobed(m.p_mii_rxd);
  set_port_slave(m.p_mii_rxd);

  set_clock_on(m.clk_mii_rx);
  set_clock_src(m.clk_mii_rx, m.p_mii_rxclk);
  set_clock_ready_src(m.clk_mii_rx, m.p_mii_rxdv);
  set_port_clock(m.p_mii_rxd, m.clk_mii_rx);
  set_port_clock(m.p_mii_rxdv, m.clk_mii_rx);

  set_clock_rise_delay(m.clk_mii_rx, CLK_DELAY_RECEIVE);

  start_clock(m.clk_mii_rx);

  clearbuf(m.p_mii_rxd);
}

#define PERIOD_BITS 30

void pcapng_timer_server(server interface pcapng_timer_interface i_tmr[num_clients], unsigned num_clients)
{
  unsigned t0;
  unsigned next_time;
  timer t;
  unsigned topbits = 0;
  t :> t0;
  next_time = t0 + (1 << PERIOD_BITS);

  while (1) {
    select {
      case i_tmr[int i].get_top_bits(unsigned int time) -> unsigned int retval: {
        if (time - t0 > (1 << PERIOD_BITS))
          retval = (topbits-1) >> (32 - PERIOD_BITS);
        else
          retval = topbits >> (32 - PERIOD_BITS);
        break;
      }
      case t when timerafter(next_time) :> void : {
        next_time += (1 << PERIOD_BITS);
        t0 += (1 << PERIOD_BITS);
        topbits++;
        break;
      }
    }
  }
}

#define STW(offset,value) \
  asm volatile("stw %0, %1[%2]"::"r"(value), "r"(dptr), "r"(offset):"memory");

void pcapng_receiver(chanend rx, pcapng_mii_rx_t &mii, client interface pcapng_timer_interface i_tmr)
{
  timer t;
  unsigned time;
  unsigned word;
  uintptr_t dptr;
  unsigned eof = 0;

  init_mii_rx(mii);

  while (1) {
    unsigned words_rxd = 0;
    rx :> dptr;
    STW(0, PCAPNG_BLOCK_ENHANCED_PACKET); // Block Type
    STW(2, mii.id); // Interface ID

    eof = 0;
    mii.p_mii_rxd when pinseq(0xD) :> int sof;

    t :> time;

    while (!eof) {
      select {
        case mii.p_mii_rxd :> word: {
          if (words_rxd < CAPTURE_WORDS)
            STW(words_rxd + 7, word);
          words_rxd += 1;
          break;
        }
        case mii.p_mii_rxdv when pinseq(0) :> int lo:
        {
          int tail;
          int taillen = endin(mii.p_mii_rxd);

          //TODO taillen > 32 ??

          eof = 1;
          mii.p_mii_rxd :> tail;
          tail = tail >> (32 - taillen);

          // The number of bytes that the packet is in its entirety
          unsigned byte_count = (words_rxd * 4) + (taillen >> 3);
          unsigned packet_len = byte_count;

          if (taillen >> 3) {
            if (words_rxd < CAPTURE_WORDS) {
              STW(words_rxd + 7, tail);
              words_rxd += 1;
            }
          }

          if (byte_count > CAPTURE_BYTES) {
            byte_count = CAPTURE_BYTES;
            words_rxd = CAPTURE_WORDS;
          }

          unsigned int total_length = (words_rxd * 4) + PCAPNG_EPB_OVERHEAD_BYTES;
          STW(1, total_length);              // Block Total Length
          STW(5, byte_count);                // Captured Len
          STW(6, packet_len);                // Packet Len
          STW(words_rxd + 7, 0);             // Options
          STW(words_rxd + 8, total_length);  // Block Total Length

          // Do this once packet reception is finished
          STW(4, time); // TimeStamp Low
          unsigned time_top_bits = i_tmr.get_top_bits(time);
          STW(3, time_top_bits); // TimeStamp High

          rx <: dptr;
          rx <: total_length;

          break;
        }
      }
    }
  }
}

