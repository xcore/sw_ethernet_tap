#ifndef __ANALYSER_H__
#define __ANALYSER_H__

#include <stdint.h>

void analyse_init();
void analyse(unsigned int buffer[]);

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

void increment_count(stream_id_t *id);
void check_counts();

#endif // __ANALYSER_H__
