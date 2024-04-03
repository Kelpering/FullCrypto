#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <gmp.h>
#include "../include/ByteArr.h"

typedef struct
{
    mpz_t Exp;
    mpz_t Mod;  // Mod is shared between keys; assume Mod is public in both keys.
} RSAKey;