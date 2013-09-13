#include <platform.h>
#include <xscope.h>
#include <stdint.h>
#include <print.h>
#include <xclib.h>
#include "util.h"
#include "xassert.h"

#define SEND_PACKET_DATA 1
#define NOTIFY_DROPPED_PACKETS 1

/*
 * Use the CAPTURE_BYTES to define the leading number of bytes that the ethernet tap captures of each frame.
 */
#define CAPTURE_BYTES 64
#define CAPTURE_WORDS (CAPTURE_BYTES / 4)

// There are 9 words (assuming only one word of options) in the enhanced packet block format
#define PCAP_NG_BYTES 36

enum pcap_ng_block_type_t {
  PCAP_NG_BLOCK_SECTION_HEADER        = 0x0A0D0D0A,
  PCAP_NG_BLOCK_INTERFACE_DESCRIPTION = 1,
  PCAP_NG_BLOCK_SIMPLE_PACKET         = 3,
  PCAP_NG_BLOCK_NAME_RESOLUTION       = 4,
  PCAP_NG_BLOCK_ENHANCED_PACKET       = 6,
};

#define NUM_TIMER_CLIENTS 2

typedef struct {
  unsigned id;
  clock clk_mii_rx;                 /**< MII RX Clock Block **/
  in port p_mii_rxclk;              /**< MII RX clock wire */
  in buffered port:32 p_mii_rxd;    /**< MII RX data wire */
  in port p_mii_rxdv;               /**< MII RX data valid wire */
} mii_rx;

// Circle slot
on tile[1]: mii_rx mii2 = {
  1,
  XS1_CLKBLK_3,
  XS1_PORT_1B,
  XS1_PORT_4A,
  XS1_PORT_1C,
};

// Square slot
on tile[1]: mii_rx mii1 = {
  0,
  XS1_CLKBLK_4,
  XS1_PORT_1J,
  XS1_PORT_4E,
  XS1_PORT_1K,
};

#define PAD_DELAY_RECEIVE    0
#define CLK_DELAY_RECEIVE    0

void init_mii_rx(mii_rx &m)
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

interface timer_interface {
  unsigned int get_top_bits(unsigned int time);
};

#define PERIOD_BITS 30

/*
 * A function to keep track of the top bits of a 64-bit counter
 */
void timer_server(server interface timer_interface i_tmr[num_clients], unsigned num_clients)
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

void receiver(chanend rx, mii_rx &mii, client interface timer_interface i_tmr)
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
    STW(0, PCAP_NG_BLOCK_ENHANCED_PACKET); // Block Type
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

          if (taillen >> 3)
            words_rxd += 1;

          if (byte_count > CAPTURE_BYTES) {
            byte_count = CAPTURE_BYTES;
            words_rxd = CAPTURE_WORDS;
          }

          STW(1, words_rxd*4+PCAP_NG_BYTES);              // Block Total Length
          STW(5, byte_count);                             // Captured Len
          STW(6, packet_len);                             // Packet Len
          STW(words_rxd + 7, 0);                          // Options
          STW(words_rxd + 8, words_rxd*4+PCAP_NG_BYTES);  // Block Total Length

          // Do this once packet reception is finished
          STW(4, time); // TimeStamp Low
          unsigned time_top_bits = i_tmr.get_top_bits(time);
          STW(3, time_top_bits); // TimeStamp High

          rx <: dptr;
          rx <: byte_count + PCAP_NG_BYTES;

          break;
        }
      }
    }
  }
}

#define BUFFER_COUNT 32
#define MAX_BUFFER_SIZE (1524+36)

static void pass_buffer_to_mii(chanend mii_c, uintptr_t free_queue[BUFFER_COUNT], unsigned &free_top_index)
{
  mii_c <: free_queue[free_top_index];
  free_top_index--;
}

static inline void process_buffer(chanend c, unsigned &work_pending,
    unsigned &pending_head_index, unsigned pending_tail_index, unsigned &free_top_index,
    uintptr_t pointer_queue[n], uintptr_t size_queue[n], uintptr_t free_queue[n], unsigned n,
    uintptr_t full_buf, unsigned &packet_dropped_count)
{
  unsigned length_in_bytes;
  c :> length_in_bytes;

  if ((pending_head_index - pending_tail_index) == BUFFER_COUNT || free_top_index == 0) {
    packet_dropped_count += 1;
    if (NOTIFY_DROPPED_PACKETS)
      xscope_int(1, packet_dropped_count);
//    assert(0);
  } else {
    unsigned index = pending_head_index % BUFFER_COUNT;
    pointer_queue[index] = full_buf;
    size_queue[index] = length_in_bytes;
    pending_head_index++;
    work_pending++;
    pass_buffer_to_mii(c, free_queue, free_top_index);
  }
}

void control(chanend mii1_c, chanend mii2_c, chanend xscope_c)
{
  unsigned char buffer[MAX_BUFFER_SIZE * BUFFER_COUNT];
  unsigned int work_pending = 0;
  unsigned int packet_dropped_count = 0;

  for (unsigned i = 0; i < MAX_BUFFER_SIZE * BUFFER_COUNT; i++) {
    buffer[i] = 0;
  }

  uintptr_t pointer_queue[BUFFER_COUNT];
  uintptr_t size_queue[BUFFER_COUNT];
  uintptr_t free_queue[BUFFER_COUNT];

  asm("mov %0, %1":"=r"(free_queue[0]):"r"(buffer));
  for (unsigned i = 1; i < BUFFER_COUNT; i++)
    free_queue[i] = free_queue[i - 1] + MAX_BUFFER_SIZE;

  unsigned pending_tail_index = 0;
  unsigned pending_head_index = 0;
  unsigned free_top_index = BUFFER_COUNT - 1;

  //start by issuing buffers to both of the miis
  pass_buffer_to_mii(mii1_c, free_queue, free_top_index);
  pass_buffer_to_mii(mii2_c, free_queue, free_top_index);

  while (1) {
    select {
      case mii1_c :> uintptr_t full_buf: {
        process_buffer(mii1_c, work_pending, pending_head_index, pending_tail_index,
            free_top_index, pointer_queue, size_queue, free_queue, BUFFER_COUNT,
            full_buf, packet_dropped_count);
        break;
      }
      case mii2_c :> uintptr_t full_buf: {
        process_buffer(mii2_c, work_pending, pending_head_index, pending_tail_index,
            free_top_index, pointer_queue, size_queue, free_queue, BUFFER_COUNT,
            full_buf, packet_dropped_count);
        break;
      }
      work_pending => default : {
        // Send a pointer out to the outputter
        unsigned index = pending_tail_index % BUFFER_COUNT;
        pending_tail_index++;

        unsigned size = size_queue[index];
        xscope_c <: size;
        if (SEND_PACKET_DATA) {
          master {
            for (unsigned i = 0; i < size/4; i++) {
              unsigned tmp;
              asm volatile("ldw %0, %1[%2]":"=r"(tmp):"r"(pointer_queue[index]), "r"(i):"memory");
              xscope_c <: tmp;
            }
          }
        }

        work_pending--;

        free_queue[free_top_index] = pointer_queue[index];
        free_top_index++;
        break;
      }
    }
  }
}

void xscope_outputter(chanend xscope_c)
{
  unsigned int buffer[(CAPTURE_BYTES + PCAP_NG_BYTES + 3)/4];
  unsigned byte_count;
  while (1) {
    xscope_c :> byte_count;
    if (SEND_PACKET_DATA) {
      slave {
        for (unsigned i = 0; i < byte_count/4; i++)
          xscope_c :> buffer[i];
      }
      xscope_bytes_c(0, byte_count, (unsigned char *)buffer);
    } else {
      xscope_int(0, byte_count);
    }
  }
}

void xscope_user_init(void) {
  xscope_register(2, XSCOPE_CONTINUOUS, "Packet Data", XSCOPE_UINT, "Value"
#if NOTIFY_DROPPED_PACKETS
      , XSCOPE_DISCRETE,   "Packet Dropped", XSCOPE_UINT, "Value"
#endif
      );
}

int main()
{
  chan c_mii1;
  chan c_mii2;
  chan c_xscope;
  interface timer_interface i_tmr[NUM_TIMER_CLIENTS];
  par {
    // xscope outputter has to be on tile 0 because otherwise the packet data gets
    // re-ordered when being sent from the outputter to the xscope server.
    on tile[0]:xscope_outputter(c_xscope);
    on tile[1]:receiver(c_mii1, mii1, i_tmr[0]);
    on tile[1]:receiver(c_mii2, mii2, i_tmr[1]);
    on tile[1]:control(c_mii1, c_mii2, c_xscope);
    on tile[1]:timer_server(i_tmr, NUM_TIMER_CLIENTS);
  }
  return 0;
}

