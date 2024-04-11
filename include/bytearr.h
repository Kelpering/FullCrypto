#ifndef BYTEARR_H
#define BYTEARR_H

#include <stddef.h>
#include <stdint.h>

typedef struct 
{
    uint8_t* Arr;
    size_t Size;
} ByteArr;

#endif // BYTEARR_H