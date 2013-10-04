#ifndef __BUFFERS_H__
#define __BUFFERS_H__

#include <xccompat.h>
#include <stdint.h>
#include "pcapng.h"
#include "pcapng_conf.h"

/* Enough room to cope with a double VLAN-tagged packet */
#define MAX_BUFFER_SIZE (1524+PCAPNG_EPB_OVERHEAD_BYTES)

typedef struct buffers_free_t {
  unsigned top_index;
  uintptr_t stack[BUFFER_COUNT];
} buffers_free_t;

void buffers_free_initialise(REFERENCE_PARAM(buffers_free_t, used));
void buffers_free_initialise_c(REFERENCE_PARAM(buffers_free_t, used));
uintptr_t buffers_free_acquire(REFERENCE_PARAM(buffers_free_t, used));
void buffers_free_release(REFERENCE_PARAM(buffers_free_t, used), uintptr_t buffer);

typedef struct buffers_used_t {
  unsigned tail_index;
  unsigned head_index;
  uintptr_t pointers[BUFFER_COUNT];
  uintptr_t length_in_bytes[BUFFER_COUNT];
} buffers_used_t;

void buffers_used_initialise(REFERENCE_PARAM(buffers_used_t, used));
void buffers_used_add(REFERENCE_PARAM(buffers_used_t, used), uintptr_t buffer, unsigned length_in_bytes);
int buffers_used_full(REFERENCE_PARAM(buffers_used_t, used));

#ifdef __XC__
{uintptr_t, unsigned} buffers_used_take(REFERENCE_PARAM(buffers_used_t, used));
#endif

#endif // __BUFFERS_H__
