#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "../include/ByteArr.h"


//* AES Standards

/// @brief Encrypts Plaintext with Key to the AES-256 standard (FIPS-197 compliant).
/// @param Plaintext 16 bytes of Plaintext to encrypt, directly altered into Ciphertext.
/// @param Key 32 bytes of a key, used to encrypt Plaintext.
void AES_STD_Enc(uint8_t* Plaintext, const uint8_t* Key);

/// @brief Decrypts Ciphertext with Key to the AES-256 standard (FIPS-197 compliant).
/// @param Ciphertext 16 bytes of Ciphertext to decrypt, directly altered into Plaintext.
/// @param Key 32 bytes of a key, used to decrypt Ciphertext.
void AES_STD_Dec(uint8_t* Ciphertext, const uint8_t* Key);


//* AES Implementations

/// @brief An ECB encryption implementation of AES-256.
/// @param Plaintext Plaintext of any size, represented as a uint8_t array.
/// @param Size The size of said uint8_t array.
/// @param Key 32-byte key to encrypt the Plaintext
/// @returns A ByteArr struct containing an allocated uint8_t array to the ciphertext, and the size of said array. The array pointer must be de-allocated to prevent memory leaks.
/// @note Will return NULL pointer and a size of 0 if invalid
ByteArr AES_ECB_Enc(const uint8_t* Plaintext, size_t Size, const uint8_t* Key);

/// @brief An ECB decryption implementation of AES-256.
/// @param Ciphertext Ciphertext of any size that is a multiple of 16, represented as a uint8_t array.
/// @param Size The size of said uint8_t array, must be a multiple of 16, else it is invalid.
/// @param Key 32-byte key to decrypt the Ciphertext
/// @returns A ByteArr struct containing an allocated uint8_t array to the plaintext, and the size of said array. The array pointer must be de-allocated to prevent memory leaks.
/// @note Will return NULL pointer and a size of 0 if invalid.
ByteArr AES_ECB_Dec(const uint8_t* Ciphertext, size_t Size, const uint8_t* Key);

/// @brief A CBC encryption implementation of AES-256.
/// @param Plaintext Plaintext of any size, represented as a uint8_t array.
/// @param Size The size of said uint8_t array.
/// @param Key 32-byte key to encrypt the Plaintext
/// @param IV A 16-byte, randomly chosen, Initialization vector. Does not have to be hidden.
/// @returns A ByteArr struct containing an allocated uint8_t array to the ciphertext, and the size of said array. The array pointer must be de-allocated to prevent memory leaks.
/// @note Will return NULL pointer and a size of 0 if invalid.
ByteArr AES_CBC_Enc(const uint8_t* Plaintext, size_t Size, const uint8_t* Key, const uint8_t* IV);

/// @brief A CBC decryption implementation of AES-256.
/// @param Ciphertext Ciphertext of any size that is a multiple of 16, represented as a uint8_t array.
/// @param Size The size of said uint8_t array, must be a multiple of 16, else it is invalid.
/// @param Key 32-byte key to decrypt the Ciphertext
/// @param IV A 16-byte, randomly chosen, Initialization vector. Does not have to be hidden.
/// @returns A ByteArr struct containing an allocated uint8_t array to the plaintext, and the size of said array. The array pointer must be de-allocated to prevent memory leaks.
/// @note Will return NULL pointer and a size of 0 if invalid.
ByteArr AES_CBC_Dec(const uint8_t* Ciphertext, size_t Size, const uint8_t* Key, const uint8_t* IV);

/// @brief Encrypts Plaintext while also generating Tag to prove that neither AAD or Ciphertext were been altered (Authenticated Encryption).
/// @param Plaintext Plaintext of any size, directly altered into Ciphertext.
/// @param PSize Size of Plaintext in bytes.
/// @param AAD Additional Authenticated Data (AAD). Not encrypted, but factored into the Tag
/// @param ASize Size of AAD in bytes.
/// @param Key 256-bit (32 byte) key.
/// @param IV 96-bit (12 byte) randomly generated value.
/// @returns An allocated 128-bit tag (16 bytes). Used to prove Ciphertext has not been altered.
uint8_t* AES_GCM_Enc(uint8_t* Plaintext, size_t PSize, const uint8_t* AAD, size_t ASize, const uint8_t* Key, const uint8_t* IV);

/// @brief Decrypts Ciphertext while also validating Tag to prove that neither AAD or Ciphertext were altered (Authenticated Decryption).
/// @param Ciphertext Ciphertext of any size, directly altered into Plaintext.
/// @param CSize Size of Ciphertext in bytes.
/// @param AAD Additional Authenticated Data (AAD) associated with Ciphertext (generated together) to validate.
/// @param ASize Size of AAD in bytes.
/// @param Tag 128-bit (16 byte) tag that validates that Ciphertext and AAD have not been altered.
/// @param Key 256-bit (32 byte) key.
/// @param IV 96-bit (12 byte) IV.
/// @returns A boolean value on whether or not the decryption was valid. If invalid, Ciphertext was not altered.
bool AES_GCM_Dec(uint8_t* Ciphertext, size_t CSize, const uint8_t* AAD, size_t ASize, const uint8_t* Tag, const uint8_t* Key, const uint8_t* IV);

/// @brief Encrypts Plaintext while also generating Tag to prove that neither the AAD or Ciphertext were altered (Authenticated Encryption).
/// @param Plaintext Plaintext of any size, directly altered into Ciphertext.
/// @param PSize Size of Plaintext in bytes.
/// @param AAD Additional Authenticated Data (AAD). Not encrypted, but factored into the Tag.
/// @param ASize Size of AAD in bytes.
/// @param Key 256-bit (32 byte) key.
/// @param IV 96-bit (12 byte) randomly generated value.
/// @returns An allocated 128-bit tag (16 bytes). Used to prove Ciphertext has not been altered.
/// @note GCM-SIV has an advantage over plain GCM in the fact that it is resistant to reusing random values for IV.
uint8_t* AES_GCM_SIV_Enc(uint8_t* Plaintext, size_t PSize, const uint8_t* AAD, size_t ASize, const uint8_t* Key, const uint8_t* IV);

/// @brief Decrypts Ciphertext while also validating Tag to prove that neither AAD or Ciphertext were altered (Authenticated Decryption).
/// @param Ciphertext Ciphertext of any size, directly altered into Plaintext.
/// @param CSize Size of Ciphertext in bytes.
/// @param AAD Additional Authenticated Data (AAD) associated with Ciphertext (generated together) to validate.
/// @param ASize Size of AAD in bytes.
/// @param Tag 128-bit (16 byte) tag that validates that Ciphertext and AAD have not been altered.
/// @param Key 256-bit (32 byte) key.
/// @param IV 96-bit (12 byte) randomly generated value.
/// @returns A boolean value on whether or not the decryption was valid. If invalid, Ciphertext was not altered.
/// @note GCM-SIV has an advantage over plain GCM in the fact that it is resistant to reusing random values for IV.
bool AES_GCM_SIV_Dec(uint8_t* Ciphertext, size_t CSize, const uint8_t* AAD, size_t ASize, const uint8_t* Tag, const uint8_t* Key, const uint8_t* IV);

//* Non-standard generator functions

/// @brief Generates a random 32-byte key for use in AES-256 functions.
/// @param Seed A 32-bit seed value for the rand generator. Recommended to use time(NULL) for the seed.
/// @returns an allocated, 32-byte array for use in AES functions. Must be de-allocated to prevent memory leaks.
/// @warning This function is insecure and should only be used for convenient testing.
uint8_t* AES_KeyGen256(uint32_t Seed);

/// @brief Generates a random 16-byte IV for use with CBC.
/// @param Seed A random number to initialize srand(). Recommended to use time(NULL).
/// @returns An allocated 16-byte array. Must be de-allocated to prevent memory leaks.
/// @warning This function is insecure, and should only be used for convenient testing.
uint8_t* AES_IVGen(uint32_t Seed, size_t Size);
