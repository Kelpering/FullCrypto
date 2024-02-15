#pragma once
#include <stdint.h>
#include <stdlib.h>

/// @brief Hashes Data with the MD5 standard. Returns 16 byte hash as a string of hexadecimal.
/// @param Data An array of bytes to be hashed
/// @param Size The size of the Data array, in bytes.
/// @param StringHash String (Char array) of minimum length 33.
/// @returns 16-Byte hash as a string of hexadecimal characters
void HashMD5(void* Data, size_t Size, char StringHash[33]);