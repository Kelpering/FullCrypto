#include "../include/FullCrypto.h"
#include <stdio.h>

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

ByteArr CBCAESEnc(const uint8_t* Plaintext, size_t Size, const uint8_t* Key, const uint8_t* IV)
{
    ByteArr NewArr;
    uint8_t PadByte = 16 - (Size%16);
    NewArr.Size = PadByte + Size;
    NewArr.Arr = malloc(NewArr.Size);

    for (size_t i = 0; i < Size; i++)
        NewArr.Arr[i] = Plaintext[i];
    for (size_t i = Size; i < NewArr.Size; i++)
        NewArr.Arr[i] = PadByte;

    for (int i = 0; i < 16; i++)
        NewArr.Arr[i] ^= IV[i];
    
    for (size_t i = 0; i < NewArr.Size; i+=16)
    {
        AESEnc(NewArr.Arr+i, Key);
        for (int j = 0; j < 16; j++)
            NewArr.Arr[i+16 + j] ^= NewArr.Arr[i + j];
    }

    return NewArr;
}

ByteArr CBCAESDec(const uint8_t* Ciphertext, size_t Size, const uint8_t* Key, const uint8_t* IV)
{
    //? Copy over Ciphertext
    uint8_t* Temp = malloc(Size);
    for (size_t i = 0; i < Size; i++)
        Temp[i] = Ciphertext[i];

    //? Decrypt Temp, 16 bytes at a time
    for (size_t i = 0; i < Size; i+=16)
        AESDec(Temp + i, Key);

    //? XOR each Ciphertext
    for (int i = 0; i < 16; i++)
        Temp[i] ^= IV[i];
    for (size_t i = 16; i < Size; i++)
        Temp[i] ^= Ciphertext[i-16];

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
