#pragma once
#include <stdint.h>
#include <stdlib.h>
#include "../include/AES.h"

typedef struct
{
    uint8_t* Arr;
    size_t  Size;
} ByteArr;

ByteArr ECBAESEnc(const uint8_t* Plaintext, size_t Size, const uint8_t* Key);
ByteArr ECBAESDec(const uint8_t* Ciphertext, size_t Size, const uint8_t* Key);