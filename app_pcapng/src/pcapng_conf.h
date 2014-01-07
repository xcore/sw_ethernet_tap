#ifndef __PCAPNG_CONF_H__
#define __PCAPNG_CONF_H__

/*
 * Use the CAPTURE_BYTES to define the leading number of bytes that the ethernet tap captures of each frame.
 */
#define CAPTURE_BYTES 128
#define CAPTURE_WORDS (CAPTURE_BYTES / 4)

/*
 * Fine tuning for the pads/clock block
 */
#define PAD_DELAY_RECEIVE    0
#define CLK_DELAY_RECEIVE    0

/*
 * Define the number of buffers available
 */
#define BUFFER_COUNT 100

#endif // __PCAPNG_CONF_H__
