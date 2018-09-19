#ifndef _BASE64_H
#define _BASE64_H
#include <stdint.h>
unsigned int b64e_size(unsigned int);
unsigned int b64d_size(unsigned int);
unsigned int b64_encode(const uint8_t*, unsigned int, unsigned char*);
unsigned int b64_decode(const unsigned char*, unsigned int, uint8_t*);
#endif
