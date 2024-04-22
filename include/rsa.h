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

// Genkeypair
// Encrypt/Decrypt (outer)

#endif // RSA_H