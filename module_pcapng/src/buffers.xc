/*
 * Buffer management for the PCAPNG library. There is one structure to
 * track free buffer pointers and one for used buffer pointers.
 */
#include "buffers.h"

void buffers_free_initialise(buffers_free_t &free)
{
  free.top_index = BUFFER_COUNT;

  buffers_free_initialise_c(free);
  for (unsigned i = 1; i < BUFFER_COUNT; i++)
    free.stack[i] = free.stack[i - 1] + MAX_BUFFER_SIZE;
}

uintptr_t buffers_free_acquire(buffers_free_t &free)
{
  free.top_index--;
  uintptr_t buffer = free.stack[free.top_index];
  return buffer;
}

void buffers_free_release(buffers_free_t &free, uintptr_t buffer)
{
  free.stack[free.top_index] = buffer;
  free.top_index++;
}

void buffers_used_initialise(buffers_used_t &used)
{
  used.head_index = 0;
  used.tail_index = 0;
}

void buffers_used_add(buffers_used_t &used, uintptr_t buffer, unsigned length_in_bytes)
{
  unsigned index = used.head_index % BUFFER_COUNT;
  used.pointers[index] = buffer;
  used.length_in_bytes[index] = length_in_bytes;
  used.head_index++;
}

{uintptr_t, unsigned} buffers_used_take(buffers_used_t &used)
{
  unsigned index = used.tail_index % BUFFER_COUNT;
  used.tail_index++;
  return {used.pointers[index], used.length_in_bytes[index]};
}

inline int buffers_used_full(buffers_used_t &used)
{
  return (used.head_index - used.tail_index) == BUFFER_COUNT;
}

