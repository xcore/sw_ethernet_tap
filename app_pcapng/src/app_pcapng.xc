#include <platform.h>
#include <xscope.h>
#include <stdint.h>
#include <print.h>
#include <xclib.h>
#include "util.h"

void xscope_user_init(void) {
      xscope_register(1,XSCOPE_CONTINUOUS, "Continuous Value 1",XSCOPE_UINT, "Value");
}

typedef struct {
	unsigned id;
    clock clk_mii_rx;            /**< MII RX Clock Block **/
    in port p_mii_rxclk;         /**< MII RX clock wire */
    in buffered port:32 p_mii_rxd; /**< MII RX data wire */
    in port p_mii_rxdv;          /**< MII RX data valid wire */
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

void init_mii_rx(mii_rx &m){
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

void timer_server(chanend c_rx0, chanend c_rx1){
	unsigned t0;
	unsigned next_time;
	timer t;
	unsigned topbits = 0;
	t :> t0;
	next_time = t0 + (1<<PERIOD_BITS);

	while(1){
		select {
			case c_rx0 :> unsigned time:{
				if(time - t0 > (1<<PERIOD_BITS)){
					c_rx0 <: (topbits-1)>>(32-PERIOD_BITS);
				} else {
					c_rx0 <: topbits>>(32-PERIOD_BITS);
				}
				break;
			}
			case c_rx1 :> unsigned time:{
				if(time - t0 > (1<<PERIOD_BITS)){
					c_rx1 <: (topbits-1)>>(32-PERIOD_BITS);
				} else {
					c_rx1 <: topbits>>(32-PERIOD_BITS);
				}
				break;
			}
			case t when timerafter(next_time) :> void :{
				next_time += (1<<PERIOD_BITS);
				t0 += (1<<PERIOD_BITS);
				topbits++;
				break;
			}
		}
	}
}

void receiver(chanend rx, mii_rx &mii, chanend c_timer_thread)
{
  timer t;
  unsigned time;
  unsigned word;
  uintptr_t dptr;
  unsigned eof = 0;

  init_mii_rx(mii);

  while (1) {
	unsigned length = 0;
	rx :> dptr;
	asm volatile("stw %0, %1[%2]"::"r"(6),"r"(dptr), "r"(0):"memory"); //Block Type
	asm volatile("stw %0, %1[%2]"::"r"(mii.id),"r"(dptr), "r"(2):"memory"); //Interface ID

	eof = 0;
	mii.p_mii_rxd when pinseq(0xD) :> int sof;
	t :> time;
	c_timer_thread <: time;

	asm volatile("stw %0, %1[%2]"::"r"(time),"r"(dptr), "r"(4):"memory"); 	//timeStamp Low

	unsigned top_time_bits;
	c_timer_thread :> top_time_bits;
    asm volatile("stw %0, %1[%2]"::"r"(top_time_bits),"r"(dptr), "r"(3):"memory"); 		//TimeStamp High

	while(!eof){
		select {
			case mii.p_mii_rxd :> word: {
			  asm volatile("stw %0, %1[%2]"::"r"(word),"r"(dptr), "r"(length+7):"memory");
			  length += 1;
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

				asm volatile("stw %0, %1[%2]"::"r"(tail),"r"(dptr), "r"(length+7):"memory");

				unsigned byte_count = (length*4) + (taillen>>3);

				if(taillen >> 3)
					length += 1;

				asm volatile("stw %0, %1[%2]"::"r"(byte_count),"r"(dptr), "r"(5):"memory");	// Captured Len
				asm volatile("stw %0, %1[%2]"::"r"(byte_count),"r"(dptr), "r"(6):"memory");  // Packet Len
				asm volatile("stw %0, %1[%2]"::"r"(length*4+36),"r"(dptr), "r"(1):"memory");  // Block Total Length
				asm volatile("stw %0, %1[%2]"::"r"(length*4+36),"r"(dptr), "r"(length + 7):"memory");  // Block Total Length
				asm volatile("stw %0, %1[%2]"::"r"(0),"r"(dptr), "r"(length + 6):"memory");  // Options

				rx <: dptr;
				rx <: byte_count;
				break;
			}
		}
	}
    }
}

#define BUFFER_COUNT 32
#define MAX_BUFFER_SIZE (1524+36)

static void pass_buffer_to_mii(chanend mii_c, uintptr_t free_queue[BUFFER_COUNT], unsigned & free_top_index){
	mii_c <: free_queue[free_top_index];
	free_top_index--;
}

void control(chanend mii1_c, chanend mii2_c, chanend xscope_c){

	unsigned char buffer[MAX_BUFFER_SIZE*BUFFER_COUNT];
	unsigned xscope_busy = 0;
	unsigned work_pending = 0;
	//start by issuing buffers to both of the miis

	for(unsigned i=0;i<MAX_BUFFER_SIZE*BUFFER_COUNT;i++){
		buffer[i] = 0;
	}

	uintptr_t p_pointer_queue[BUFFER_COUNT];
	uintptr_t p_size_queue[BUFFER_COUNT];

	uintptr_t free_queue[BUFFER_COUNT];

	asm("mov %0, %1":"=r"(free_queue[0]):"r"(buffer));
	for(unsigned i=1;i<BUFFER_COUNT;i++)
		free_queue[i] = free_queue[i-1] + MAX_BUFFER_SIZE;

	unsigned pending_tail_index=0;
	unsigned pending_head_index=0;
	unsigned free_top_index=BUFFER_COUNT-1;

	pass_buffer_to_mii(mii1_c, free_queue, free_top_index);
	pass_buffer_to_mii(mii2_c, free_queue, free_top_index);

	while(1){
		select {
			case mii1_c :> uintptr_t full_buf:{
				unsigned length_in_bytes;
				mii1_c :> length_in_bytes;

				if(pending_head_index -pending_tail_index == BUFFER_COUNT ||
						free_top_index == 0){
					//drop the packet - the buffer is full
					//TODO warn
				} else {
					unsigned index = pending_head_index%BUFFER_COUNT;
					p_pointer_queue[index] = full_buf;
					p_size_queue[index] = length_in_bytes;
					pending_head_index++;
					work_pending++;
					pass_buffer_to_mii(mii1_c, free_queue, free_top_index);
				}
				break;
			}
			case mii2_c :> uintptr_t full_buf:{
				unsigned length_in_bytes;
				mii2_c :> length_in_bytes;

				if(pending_head_index -pending_tail_index == BUFFER_COUNT||
						free_top_index == 0){
					//drop the packet - the buffer is full
					//TODO warn
				} else {
					unsigned index = pending_head_index%BUFFER_COUNT;
					p_pointer_queue[index] = full_buf;
					p_size_queue[index] = length_in_bytes;
					pending_head_index++;
					work_pending++;
					pass_buffer_to_mii(mii2_c, free_queue, free_top_index);
				}
				break;
			}
			case xscope_c :> uintptr_t buf :{
				free_queue[free_top_index] = buf;
				xscope_busy = 0;
				free_top_index++;
				break;
			}
			work_pending && !xscope_busy=> default :{
				//send a pointer out to the outputter
				unsigned index = pending_tail_index%BUFFER_COUNT;
				pending_tail_index++;


				xscope_c <: p_pointer_queue[index];
				xscope_c <: p_size_queue[index];

				work_pending--;
				xscope_busy = 1;
				break;
			}
		}
	}



}

void xscope_outputter(chanend xscope_c){
	uintptr_t dptr;
    unsigned byte_count;
	while(1){
		xscope_c :> dptr;
		xscope_c :> byte_count;
		for(unsigned i=0;i<byte_count;i++){
			unsigned char data;
			//asm("ld8u %0, %1[%2]":"=r"(data):"r"(dptr), "r"(i));
			//printhexln(data);
		}

		xscope_bytes_c(0, byte_count, dptr);
		xscope_c <: dptr;
	}
}

int main(){
	chan mii1_c;
	chan mii2_c;
	chan xscope_c;
	chan c_timer0, c_timer1;
	par {
		on tile[1]: xscope_outputter(xscope_c);
		on tile[1]: receiver(mii1_c, mii1, c_timer0);
		on tile[1]: receiver(mii2_c, mii2, c_timer1);
		on tile[1]: control(mii1_c, mii2_c, xscope_c);
		on tile[1]: timer_server(c_timer0, c_timer1);
	}
	return 0;
}
