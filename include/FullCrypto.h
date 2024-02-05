#pragma once
#include <stdint.h>
#include <stdlib.h>
#include "../include/AES.h"

typedef struct
{
    uint8_t* Arr;
    size_t  Size;
} ByteArr;

uint8_t* ECBAESEnc(uint8_t* Plaintext, size_t Size, uint8_t* Key);
uint8_t* ECBAESDec(uint8_t* Ciphertext, size_t Size, uint8_t* Key);