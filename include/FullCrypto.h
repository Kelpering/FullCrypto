#pragma once
#include <stdint.h>
#include <stdlib.h>

uint8_t* ECBAESEnc(uint8_t* Plaintext, size_t Size, uint8_t* Key);
