#ifndef __ANALYSER_H__
#define __ANALYSER_H__

#ifdef __XC__
extern "C" {
#endif

#include <stdint.h>

void analyse_init();
void analyse(const unsigned char *buffer, const unsigned int length_in_bytes);

typedef struct {
  uint32_t low;
  uint32_t high;
} stream_id_t;

typedef struct {
  stream_id_t id;
  uint32_t count;
  uint32_t last_count;
  uint32_t snapshot;
} stream_count_t;

void check_counts(unsigned int now);

#ifdef __XC__
}
#endif

#endif // __ANALYSER_H__
