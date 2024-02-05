#include "../include/FullCrypto.h"

// ECB AES256

// CBC AES256

uint8_t* ECBAESEnc(uint8_t* Plaintext, size_t Size, uint8_t* Key)
{
    //! Needs testing
    uint8_t PadByte = 16 - (Size%16);
    uint8_t* NewPT = malloc(PadByte + Size);

    for (size_t i = 0; i < Size; i++)
        NewPT[i] = Plaintext[i];
    for (size_t i = Size; i < Size+PadByte; i++)
        NewPT[i] = PadByte;

    for (size_t i = 0; i < Size+PadByte; i+=16)
        AESEnc(NewPT + i, Key);

    // Pad data with the number equal to pad bytes (minimum 1, maximum 16)
    // Copy to new buffer. Recommend in documentation to free Plaintext.
    // Loop through all

    //! Needs to be de-allocated
    return NewPT;
}

ByteArr ECBAESDec(uint8_t* Ciphertext, size_t Size, uint8_t* Key)
{
    for (size_t i = 0; i < Size; i+=16)
        AESDec(Ciphertext + i, Key);

    uint8_t PadByte = Ciphertext[Size-1];
    uint8_t* NewCT = malloc(Size-PadByte);
    for (size_t i = 0; i < Size-PadByte; i++)
        NewCT[i] = Ciphertext[i];

    return NewCT;
}
