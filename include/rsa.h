#ifndef RSA_H
#define RSA_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmp.h>
#include "../include/bytearr.h"
#include "../include/error.h"
#include "../include/hash.h"

typedef struct
{
    mpz_t Exp;
    mpz_t Mod;  // Mod is shared between keys; assume Mod is public in both keys.
} RSAKey;

ErrorCode rsa_encode(uint8_t* Arr, size_t Size, mpz_t RetNum);

ErrorCode rsa_decode(mpz_t Num, ByteArr* RetArr);

#endif // RSA_H