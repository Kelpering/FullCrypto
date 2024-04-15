#ifndef BYTEARR_H
#define BYTEARR_H

#include <stddef.h>
#include <stdint.h>

/// @brief A struct to return a variable array of bytes.
/// @param Arr A pointer to the beginning of the byte array.
/// @param Size Size of the array in bytes.
typedef struct 
{
    uint8_t* Arr;
    size_t Size;
} ByteArr;

#endif // BYTEARR_H