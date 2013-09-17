#ifndef UTIL_H_
#define UTIL_H_

#ifdef __XC__
extern "C" {
#endif

void xscope_bytes_c(unsigned char id, unsigned int size,  const unsigned char *data);

#ifdef __XC__
}
#endif

#endif /* UTIL_H_ */
