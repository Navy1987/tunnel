#ifndef	_CRYPT_H
#define	_CRYPT_H

#include <stdint.h>

void crypt_encode(const uint8_t *key_text, size_t key_sz, uint8_t *data, size_t datasz);
void crypt_decode(const uint8_t *key_text, size_t key_sz, uint8_t *data, size_t datasz);


#endif

