/**
 * \brief   Functions to perform packet inspection and analysis.
 */

#ifndef __ANALYSER_H__
#define __ANALYSER_H__

#ifdef __XC__
extern "C" {
#endif

#include <stdint.h>

/**
 * \brief   Initialise the state of the analyser. Must be called before any of
 *          the other functions in this file.
 */
void analyse_init();

/**
 * \brief   Analyse a packet buffer. Determine if it is AVB audio data, and
 *          if it is then increment the count for that stream.
 * \param   buffer            Pointer to the packet buffer.
 * \param   length_in_bytes   Number of bytes in the buffer.
 */
void analyse_buffer(const unsigned char *buffer, const unsigned int length_in_bytes);

/**
 * \var     typedef steam_id_t
 * \brief   Structure to hold an AVB stream ID.
 */
typedef struct {
  uint32_t low;
  uint32_t high;
} stream_id_t;

/**
 * \var     typedef stream_state_t
 * \brief   State that is tracked for each active stream.
 */
typedef struct {
  stream_id_t id;                 // Stream ID. A valid stream is non-zero
  int active;                     // Determines whether the stream should be checked
  unsigned int packet_num_bytes;  // Used to detect invalid packets and determine
                                  // valid packet rate when stream is oversubscribed
  unsigned int count;             // Packet count in the current window
  unsigned int last_count;        // Packet count in the last window
  unsigned int snapshot;          // Used to record a snapshot of the packet count
                                  // for checking
  unsigned char sequence_number;  // Record the sequence number of packets to check
                                  // none go missing
} stream_state_t;

/**
 * \brief   Should be called once a second to validate the counts per stream.
 */
void check_counts(int oversubscribed, int debug);

#ifdef __XC__
}
#endif

#endif // __ANALYSER_H__
