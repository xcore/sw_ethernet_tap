#include <xscope.h>
#include <stdint.h>
#include "util.h"

void xscope_bytes_c(unsigned char id, unsigned int size, const unsigned char *data)
{
  for (unsigned i = 0; i < size; i++)
    xscope_char(id, data[i]);
}
