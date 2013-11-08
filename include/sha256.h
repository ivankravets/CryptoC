#ifndef Sha256_h
#define Sha256_h

#include <inttypes.h>
#include "Print.h"

#define HASH_LENGTH 32
#define BLOCK_LENGTH 64

#define BUFFER_SIZE 64

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

#define ror32(number, bits) ((number << (32-bits)) | (number >> bits))

union _buffer {
    uint8_t b[BLOCK_LENGTH];
    uint32_t w[BLOCK_LENGTH/4];
};
union _state {
    uint8_t b[HASH_LENGTH];
    uint32_t w[HASH_LENGTH/4];
};

void init_hmac(const uint8_t* key, int key_length);
uint8_t* result(void);
uint8_t* result_hmac(void);
void hash_block(uint8_t data);

#endif


