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

class Sha256Class : public Print
{
    public:
        void init(void);
        void initHmac(const uint8_t* secret, int secretLength);
        uint8_t* result(void);
        uint8_t* resultHmac(void);
#if defined(ARDUINO) && ARDUINO >= 100
        virtual size_t write(uint8_t);
#else
        virtual void write(uint8_t);
#endif
        using Print::write;
    private:
        void pad();
        void addUncounted(uint8_t data);
        void hashBlock();
        _buffer buffer;
        uint8_t bufferOffset;
        _state state;
        uint32_t byteCount;
        uint8_t keyBuffer[BLOCK_LENGTH];
        uint8_t innerHash[HASH_LENGTH];
};

extern Sha256Class Sha256;

#endif


