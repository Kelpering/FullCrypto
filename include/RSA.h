#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmp.h>

typedef struct
{
    mpz_t Exp;
    mpz_t Mod;  // Mod is shared between keys; assume Mod is public in both keys.
} RSAKey;