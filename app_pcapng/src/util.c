#include <xscope.h>
#include <stdint.h>

void xscope_bytes_c(unsigned char id, unsigned int size,  uintptr_t data){
	xscope_bytes(id, size, (unsigned char *)data);
}
