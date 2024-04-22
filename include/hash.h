#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stdlib.h>
#include "../include/error.h"

/// @brief A struct for interchanging hash functions as a parameter.
/// @param HashFunc A pointer to the Hash function being defined.
/// @param RetSize Size of RetArr array in bytes.
typedef struct
{
    ErrorCode (*HashFunc)(void* Data, size_t Size, uint8_t* RetArr);
    size_t HashSize;
} HashParam;

/// @brief Hashes Data of variable size with the MD5 standard.
/// @param Data An array of bytes to be hashed.
/// @param Size The size of the Data array, in bytes.
/// @param RetArr Pre-allocated array of 16 bytes to hold hash.
/// @returns Error codes (Finish when rewrite).
ErrorCode hash_md5(void* Data, size_t Size, uint8_t* RetArr);
extern HashParam MD5Param;

#endif // MD5_H