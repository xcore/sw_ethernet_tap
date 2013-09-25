#include <xscope.h>
#include <stdint.h>
#include "util.h"

void xscope_bytes_c(unsigned char id, unsigned int length_in_bytes, const unsigned char *data)
{
  xscope_bytes(0, length_in_bytes, (unsigned char *)data);
}
