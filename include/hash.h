#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stdlib.h>
#include "../include/error.h"

/// @brief Hashes Data of variable size with the MD5 standard.
/// @param Data An array of bytes to be hashed.
/// @param Size The size of the Data array, in bytes.
/// @param RetArr Pre-allocated array of 16 bytes to hold hash.
/// @returns Error codes (Finish when rewrite).
ErrorCode hash_md5(void* Data, size_t Size, uint8_t* RetArr);

#endif // MD5_H