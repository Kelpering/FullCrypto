#pragma once
#include <stdint.h>
#include <stdlib.h>
#include "../include/AES.h"

typedef struct
{
    uint8_t* Arr;
    size_t  Size;
} ByteArr;

/// @brief An ECB encryption implementation of AES-256.
/// @param Plaintext Plaintext of any positive size, represented as a uint8_t array.
/// @param Size The size of said uint8_t array.
/// @param Key 32-byte key to encrypt the Plaintext
/// @returns A ByteArr struct containing an allocated uint8_t array to the ciphertext, and the size of said array. The array pointer must be de-allocated to prevent memory leaks.
/// @note Will return NULL pointer and a size of 0 if invalid
ByteArr ECBAESEnc(const uint8_t* Plaintext, size_t Size, const uint8_t* Key);

/// @brief An ECB decryption implementation of AES-256.
/// @param Ciphertext Ciphertext of any size that is a multiple of 16, represented as a uint8_t array.
/// @param Size The size of said uint8_t array, must be a multiple of 16, else it is invalid.
/// @param Key 32-byte key to decrypt the Ciphertext
/// @returns A ByteArr struct containing an allocated uint8_t array to the plaintext, and the size of said array. The array pointer must be de-allocated to prevent memory leaks.
/// @note Will return NULL pointer and a size of 0 if invalid.
ByteArr ECBAESDec(const uint8_t* Ciphertext, size_t Size, const uint8_t* Key);

/// @brief A CBC encryption implementation of AES-256.
/// @param Plaintext Plaintext of any positive size, represented as a uint8_t array.
/// @param Size The size of said uint8_t array.
/// @param Key 32-byte key to encrypt the Plaintext
/// @param IV A 16-byte, randomly chosen, Initialization vector. Does not have to be hidden.
/// @returns A ByteArr struct containing an allocated uint8_t array to the ciphertext, and the size of said array. The array pointer must be de-allocated to prevent memory leaks.
/// @note Will return NULL pointer and a size of 0 if invalid.
ByteArr CBCAESEnc(const uint8_t* Plaintext, size_t Size, const uint8_t* Key, const uint8_t* IV);

/// @brief A CBC decryption implementation of AES-256.
/// @param Ciphertext Ciphertext of any size that is a multiple of 16, represented as a uint8_t array.
/// @param Size The size of said uint8_t array, must be a multiple of 16, else it is invalid.
/// @param Key 32-byte key to decrypt the Ciphertext
/// @param IV A 16-byte, randomly chosen, Initialization vector. Does not have to be hidden.
/// @returns A ByteArr struct containing an allocated uint8_t array to the plaintext, and the size of said array. The array pointer must be de-allocated to prevent memory leaks.
/// @note Will return NULL pointer and a size of 0 if invalid.
ByteArr CBCAESDec(const uint8_t* Ciphertext, size_t Size, const uint8_t* Key, const uint8_t* IV);

/// @brief Generates a random IV for use with CBC.
/// @param Seed A random number to initialize srand(). Recommended to use time(NULL).
/// @returns An allocated 16-byte array. Must be de-allocated to prevent memory leaks.
/// @warning This function is insecure, and should only be used for testing.
uint8_t* IVGen(uint32_t Seed);