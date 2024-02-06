#include "../include/FullCrypto.h"
#include <stdio.h>

// CBC AES256

ByteArr ECBAESEnc(const uint8_t* Plaintext, size_t Size, const uint8_t* Key)
{
    //? Declare variables & ByteArr struct
    ByteArr NewArr;
    uint8_t PadByte = 16 - (Size%16);
    NewArr.Size = Size + PadByte;
    NewArr.Arr = malloc(NewArr.Size);

    //? Copy over Plaintext to NewArr, then Pad to a multiple of 16
    for (size_t i = 0; i < Size; i++)
        NewArr.Arr[i] = Plaintext[i];
    for (size_t i = Size; i < NewArr.Size; i++)
        NewArr.Arr[i] = PadByte;

    //? Encrypt each 16 byte block.
    for (size_t i = 0; i < NewArr.Size; i+=16)
        AESEnc(NewArr.Arr + i, Key);

    //! Needs to be de-allocated
    return NewArr;
}

ByteArr ECBAESDec(const uint8_t* Ciphertext, size_t Size, const uint8_t* Key)
{
    //? Copy over Ciphertext
    uint8_t* Temp = malloc(Size);
    for (size_t i = 0; i < Size; i++)
        Temp[i] = Ciphertext[i];

    //? Decrypt Temp, 16 bytes at a time
    for (size_t i = 0; i < Size; i+=16)
        AESDec(Temp + i, Key);

    //? Declare ByteArr Struct
    ByteArr NewArr;
    NewArr.Size = Size - Temp[Size-1];
    NewArr.Arr = malloc(NewArr.Size);

    //? Copy over Temp to ByteArr
    for (size_t i = 0; i < Size-Temp[Size-1]; i++)
        NewArr.Arr[i] = Temp[i];

    //? Free allocated Temp
    free (Temp);

    //! Needs to be de-allocated
    return NewArr;
}
