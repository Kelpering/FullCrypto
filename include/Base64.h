#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "../include/ByteArr.h"



/// @brief Checks whether a string is Base64 encoding.
/// @param B64String Null terminated string.
/// @returns A boolean True/False.
bool ValidateB64(const char* B64String);

/// @brief Translates a Base64 string into a byte array.
/// @param B64String A Base64 string to be translated, null terminated.
/// @returns A ByteArr struct, containing an allocated uint8_t array pointer and the Size of said array.
/// @warning Returns an allocated array. MUST be de-allocated to prevent memory leak.
/// @note If B64String is found to be an invalid Base64 string, the function returns (ByteArr) {NULL, 0}.
ByteArr B64toByte(const char* B64String);

/// @brief Translate a byte array into a Base64 string.
/// @param Array A byte array to be translated to Base64.
/// @param Size The size of the byte array to translate.
/// @returns An allocated Base64, null terminated string.
/// @warning Returns an allocated string. MUST be de-allocated to prevent memory leak.
char* BytetoB64(const uint8_t* Array, size_t Size);