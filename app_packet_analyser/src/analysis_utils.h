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
void analyse_buffer(const unsigned char *buffer);

/**
 * \var     typedef stream_state_t
 * \brief   State that is tracked for each interface
 */
typedef struct {
  uint64_t total_byte_count;
  uint64_t total_packet_count;
  uint32_t interface_id;
  uint32_t byte_count;             // Byte count in the current window
  uint32_t byte_snapshot;
  uint32_t packet_count;           // Packet count in the current window
  uint32_t packet_snapshot;
} interface_state_t;

void check_counts();

#ifdef __XC__
}
#endif

#endif // __ANALYSER_H__
