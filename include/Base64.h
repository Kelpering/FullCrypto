#ifndef BASE64_H
#define BASE64_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "../include/ByteArr.h"
#include "../include/error.h"



/// @brief Checks whether a string is Base64 encoding.
/// @param B64String Null terminated string.
/// @returns A boolean True/False.
bool base64_validate(const char* B64String);

/// @brief Translates a Base64 string into a byte array.
/// @param B64String A Base64 string to be translated, null terminated.
/// @param Ret A ByteArr pointer, returns with an allocated arrray. Upon error, ByteArr might be overwritten with invalid data.
/// @returns ErrorCode (success, unknown, malloc)
ErrorCode base64_convert_byte(const char* B64String, ByteArr *Ret);

/// @brief Translate a byte array into a Base64 string.
/// @param Array A byte array to be translated to Base64.
/// @param Size The size of the byte array to translate.
/// @returns An allocated Base64, null terminated string.
/// @warning Returns an allocated string. MUST be de-allocated to prevent memory leak.
char* base64_convert_string(const uint8_t* Array, size_t Size);

#endif // BASE64_H