/*
 * Buffer management for the PCAPNG library. There is one structure to
 * track free buffer pointers and one for used buffer pointers.
 */
#include "buffers.h"

unsigned char g_buffer[MAX_BUFFER_SIZE * BUFFER_COUNT];

void buffers_free_initialise_c(buffers_free_t *free)
{
  free->stack[0] = (uintptr_t)g_buffer;
}

