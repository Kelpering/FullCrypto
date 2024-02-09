#pragma once
#include <stdint.h>
#include <stdlib.h>

/// @brief Encrypts Plaintext with Key to the AES-256 standard (FIPS-197 compliant).
/// @param Plaintext 16 bytes of Plaintext to encrypt, directly altered into Ciphertext.
/// @param Key 32 bytes of a key, used to encrypt Plaintext.
void AESEnc(uint8_t* Plaintext, const uint8_t* Key);

/// @brief Decrypts Ciphertext with Key to the AES-256 standard (FIPS-197 compliant).
/// @param Ciphertext 16 bytes of Ciphertext to decrypt, directly altered into Plaintext.
/// @param Key 32 bytes of a key, used to decrypt Ciphertext.
void AESDec(uint8_t* Ciphertext, const uint8_t* Key);

/// @brief Generates a random 32-byte key for use in AES functions.
/// @param Seed A 32-bit seed value for the rand generator. Recommended to use time(NULL) for the seed.
/// @returns an allocated, 32-byte array for use in AES functions. Must be de-allocated to prevent memory leaks.
/// @warning This function is insecure and should only be used for testing.
uint8_t* AESKeyGen256(uint32_t Seed);