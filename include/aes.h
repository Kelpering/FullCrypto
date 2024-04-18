#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "../include/bytearr.h"
#include "../include/error.h"


//* AES Standards

/// @brief Encrypts Plaintext with Key to the AES-256 standard.
/// @param Plaintext 16 bytes of Plaintext to encrypt, directly altered into Ciphertext.
/// @param Key 32 bytes of a key, used to encrypt Plaintext.
/// @returns ErrorCode (success, malloc_error)
ErrorCode aes_std_enc(uint8_t* Plaintext, const uint8_t* Key);

/// @brief Decrypts Ciphertext with Key to the AES-256 standard.
/// @param Ciphertext 16 bytes of Ciphertext to decrypt, directly altered into Plaintext.
/// @param Key 32 bytes of a key, used to decrypt Ciphertext.
/// @returns ErrorCode (success, malloc_error)
ErrorCode aes_std_dec(uint8_t* Ciphertext, const uint8_t* Key);


//* AES Implementations

/// @brief An ECB encryption implementation of AES-256.
/// @param Plaintext Plaintext of any size, represented as a uint8_t array.
/// @param Size The size of said uint8_t array.
/// @param Key 32-byte key to encrypt the Plaintext
/// @param Ret A ByteArr struct with the return info within it. User must de-allocate Ret->Arr to prevent memory leak.
/// @returns ErrorCode (success, unknown_error, malloc_error)
ErrorCode aes_ecb_enc(const uint8_t* Plaintext, size_t Size, const uint8_t* Key, ByteArr* Ret);

/// @brief An ECB decryption implementation of AES-256.
/// @param Ciphertext Ciphertext of any size that is a multiple of 16, represented as a uint8_t array.
/// @param Size The size of said uint8_t array, must be a multiple of 16, else it is invalid.
/// @param Key 32-byte key to decrypt the Ciphertext
/// @param Ret A ByteArr struct with the return info within it. User must de-allocate Ret->Arr to prevent memory leak.
/// @returns ErrorCode (success, unknown_error, malloc_error)
ErrorCode aes_ecb_dec(const uint8_t* Ciphertext, size_t Size, const uint8_t* Key, ByteArr* Ret);

/// @brief A CBC encryption implementation of AES-256.
/// @param Plaintext Plaintext of any size, represented as a uint8_t array.
/// @param Size The size of said uint8_t array.
/// @param Key 32-byte key to encrypt the Plaintext
/// @param IV A 16-byte, randomly chosen, Initialization vector. Does not have to be hidden.
/// @param Ret A ByteArr struct with the return info within it. User must de-allocate Ret->Arr to prevent memory leak.
/// @returns ErrorCode (success, unknown_error, malloc_error)
ErrorCode aes_cbc_enc(const uint8_t* Plaintext, size_t Size, const uint8_t* Key, const uint8_t* IV, ByteArr* Ret);

/// @brief A CBC decryption implementation of AES-256.
/// @param Ciphertext Ciphertext of any size that is a multiple of 16, represented as a uint8_t array.
/// @param Size The size of said uint8_t array, must be a multiple of 16, else it is invalid.
/// @param Key 32-byte key to decrypt the Ciphertext
/// @param IV A 16-byte, randomly chosen, Initialization vector. Does not have to be hidden.
/// @param Ret A ByteArr struct with the return info within it. User must de-allocate Ret->Arr to prevent memory leak.
/// @returns ErrorCode (success, unknown_error, malloc_error)
ErrorCode aes_cbc_dec(const uint8_t* Ciphertext, size_t Size, const uint8_t* Key, const uint8_t* IV, ByteArr* Ret);

/// @brief Encrypts Plaintext while also generating Tag to prove that neither AAD or Ciphertext were been altered (Authenticated Encryption).
/// @param Plaintext Plaintext of any size, directly altered into Ciphertext.
/// @param PSize Size of Plaintext in bytes.
/// @param AAD Additional Authenticated Data (AAD). Not encrypted, but factored into the Tag
/// @param ASize Size of AAD in bytes.
/// @param Key 256-bit (32 byte) key.
/// @param IV 96-bit (12 byte) randomly generated value.
/// @param Tag A pointer to a 128-bit (16 byte) tag that validates that Ciphertext and AAD have not been altered. Must be de-allocated by the user to prevent memory leaks.
/// @returns ErrorCode (success, unknown_error, malloc_error)
ErrorCode aes_gcm_enc(uint8_t* Plaintext, size_t PSize, const uint8_t* AAD, size_t ASize, const uint8_t* Key, const uint8_t* IV, uint8_t** RetTag);

/// @brief Decrypts Ciphertext while also validating Tag to prove that neither AAD or Ciphertext were altered (Authenticated Decryption).
/// @param Ciphertext Ciphertext of any size, directly altered into Plaintext.
/// @param CSize Size of Ciphertext in bytes.
/// @param AAD Additional Authenticated Data (AAD) associated with Ciphertext (generated together) to validate.
/// @param ASize Size of AAD in bytes.
/// @param Key 256-bit (32 byte) key.
/// @param IV 96-bit (12 byte) IV.
/// @param Tag 128-bit (16 byte) tag that validates that Ciphertext and AAD have not been altered.
/// @returns ErrorCode (Success, unknown_error, malloc_error)
ErrorCode aes_gcm_dec(uint8_t* Ciphertext, size_t CSize, const uint8_t* AAD, size_t ASize, const uint8_t* Key, const uint8_t* IV, const uint8_t* Tag);

/// @brief Encrypts Plaintext while also generating Tag to prove that neither the AAD or Ciphertext were altered (Authenticated Encryption).
/// @param Plaintext Plaintext of any size, directly altered into Ciphertext.
/// @param PSize Size of Plaintext in bytes.
/// @param AAD Additional Authenticated Data (AAD). Not encrypted, but factored into the Tag.
/// @param ASize Size of AAD in bytes.
/// @param Key 256-bit (32 byte) key.
/// @param IV 96-bit (12 byte) randomly generated value.
/// @param Tag A pointer to a 128-bit (16 byte) tag that validates that Ciphertext and AAD have not been altered.
/// @returns ErrorCode (Success, unknown_error, malloc_error)
/// @note GCM-SIV has an advantage over plain GCM in the fact that it is resistant to reusing random values for IV.
ErrorCode aes_siv_enc(uint8_t* Plaintext, size_t PSize, const uint8_t* AAD, size_t ASize, const uint8_t* Key, const uint8_t* IV, uint8_t** RetTag);

/// @brief Decrypts Ciphertext while also validating Tag to prove that neither AAD or Ciphertext were altered (Authenticated Decryption).
/// @param Ciphertext Ciphertext of any size, directly altered into Plaintext.
/// @param CSize Size of Ciphertext in bytes.
/// @param AAD Additional Authenticated Data (AAD) associated with Ciphertext (generated together) to validate.
/// @param ASize Size of AAD in bytes.
/// @param Tag 128-bit (16 byte) tag that validates that Ciphertext and AAD have not been altered.
/// @param Key 256-bit (32 byte) key.
/// @param IV 96-bit (12 byte) randomly generated value.
/// @returns ErrorCode (Success, unknown_error, malloc_error)
/// @note GCM-SIV has an advantage over plain GCM in the fact that it is resistant to reusing random values for IV.
ErrorCode aes_siv_dec(uint8_t* Ciphertext, size_t CSize, const uint8_t* AAD, size_t ASize, const uint8_t* Key, const uint8_t* IV, const uint8_t* Tag);

//* Non-standard generator functions

/// @brief Generates a random 16-byte IV for use with CBC.
/// @param Seed A random number to initialize srand(). Recommended to use time(NULL).
/// @returns An allocated 16-byte array. Must be de-allocated to prevent memory leaks.
/// @note Standard AES key here is a Size of 32 bytes.
/// @warning This function is insecure, and should only be used for convenient testing.
uint8_t* aes_generate_iv(uint32_t Seed, size_t Size);

#endif // AES_H