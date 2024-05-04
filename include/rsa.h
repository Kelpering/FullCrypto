#ifndef RSA_H
#define RSA_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <gmp.h>
#include "../include/bytearr.h"
#include "../include/error.h"
#include "../include/hash.h"

typedef struct
{
    mpz_t Exp;
    mpz_t Mod;  // Mod is shared between keys; assume Mod is public in both keys.
} RSAKey;

ErrorCode rsa_generate_keypair(size_t BitSize, RSAKey* Public, RSAKey* Private);

ErrorCode rsa_oaep_enc(const uint8_t* Plaintext, size_t PSize, const uint8_t* IV, const RSAKey PubKey, const HashParam HashFunc, ByteArr* RetArr);

ErrorCode rsa_oaep_dec(const uint8_t* Ciphertext, size_t CSize, const RSAKey PrivKey, const HashParam HashFunc, ByteArr* RetArr);


#endif // RSA_H