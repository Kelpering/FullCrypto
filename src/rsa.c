#include "../include/rsa.h"
#include "../include/rsa_private.h"
#include <stdio.h>

//? Ordered by priority
//* encode/decode
//* encrypt/decrypt (raw, macro)
//* mgf_1
//^ oaep pass (mpz_t)
//^ encrypt/decrypt (oaep, Text*)
//^ sign/verify


// To all: Assume that all inputs are valid
// Only check if internal error would be caused.

// Encrypt mpz_t Plaintext
// Plaintext < mpz_t Modulus (N)
// Return mpz_t Ciphertext
// Plaintext type == Ciphertext type
// Overwrite Plaintext into Ciphertext

// Decrypt mpz_t Ciphertext
// Ciphertext < mpz_t Modulus (N)
// Return Plaintext
// Plaintext type == Ciphertext type
// Overwrite Ciphertext into Plaintext

// byte arr (Data) -> mpz_t (encoded)

// mpz_t (encoded) -> byte arr (Data)

// GenerateKeyPair
// mpz_t encoded
// N, E (Public Modulus, Public Exponent)
// D (Private Exponent)
// This should all be contained within PrivateKey (contains PublicKey Struct)

//* RSA encrypt & decrypt will use OAEP (Optimal Asymmetric Encryption Padding) on the message
//* RSA Sign will use MD5 hashing (for now)

// void GenerateKeyPair(const uint64_t Seed, RSAKey Public, RSAKey Private)
// {
//     // 4096-bit
//     // Generate all required values for a keypair, save them to the keys
// }

// void RSA_Sign(const mpz_t Message, mpz_t Sign, const RSAKey Private)
// {
//     // Sign = RSAEncrypt(Hash(Text), Private)
//     // This means the hash can be decrypted via the public key
//     // The hash prevents modification without detection
//     // Directly change mpz_t Sign
//     //* Convert mpz_t Message into Array via Decode (temporarily) 
//     ByteArr TempDecode = DecodeArray(Message);
//     uint8_t Hash[16] = {0};

// }

// bool RSA_Verify(const mpz_t Text, const mpz_t Sign, const RSAKey Public)
// {
//     // Sign = RSADecrypt(Sign, Public)  (Proves private encrypted it)
//     // NewSign = Hash(Text)       (Hash Text)
//     // Return (Sign == NewSign)         If Ciphertext is altered, hash wont match. If Sign is altered, RSA decrypt wont match
// }

// Function: void mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op)
// Set rop from an array of word data at op.

// The parameters specify the format of the data. count many words are read, each size bytes. order can be 1 for most significant word first or -1 
// for least significant first. Within each word endian can be 1 for most significant byte first, -1 for least significant first, or 0 for the native 
// endianness of the host CPU. The most significant nails bits of each word are skipped, this can be 0 to use the full words.



// mpz_t EncodeArray(uint8_t* Array, size_t Size)
// {

// }

// ByteArr DecodeArray(mpz_t Num)
// {
//     // type DecodeArray(mpz_t Number)
// // Return (decide later) Byte array that contains the mpz_t number decoded
// // Depending on how the number has to be encoded/decoded, this might just be the equivalent GMP function
// }

//? Refactored core

// Decide Keysize, modsize(?), messagesize(?), and whether or not the user will be responsible for checking messagesize

//^ Priority: 2
// Generate a keypair for rsa enc, dec, sign.
ErrorCode rsa_generate_keypair();

//^ Priority: 1
//! Use RSA_Encrypt for testing purposes
// encrypt Plaintext -> Ciphertext with RSA-OAEP
ErrorCode rsa_oaep_enc(const uint8_t* Plaintext, size_t PSize, const uint8_t* IV, const RSAKey PubKey, const HashParam HashFunc, ByteArr* RetArr)
{
    //? Length checking and setup
    // Size of PubKey.Mod in bytes (k in RFC)
    size_t ModSize = (mpz_sizeinbase(PubKey.Mod, 2) + 7) >> 3;
    printf("ModSize: %ld\n", ModSize);

    // Length Check: Either PSize is too large, or the equation is negative (edge case)
    if (PSize > (size_t) ((ModSize)-(2*HashFunc.Size) - 2) || (ptrdiff_t) ((ModSize)-(2*HashFunc.Size) - 2) < 0)
        return length_error;
    
    // EncodedMessage is the entire message with both Seed and DB Mask included.
    uint8_t* EncodedMessage = calloc(ModSize, 1);
    if (EncodedMessage == NULL)
        return malloc_error;

    //? Data Block (DB)
    // EMPos is used to represent where we are within EncodedMessage
    // Starting at 1+HashFunc.Size starts us where the DB (DataBlock) begins
    size_t EMPos = 1+HashFunc.Size;

    // lHash (Label is not provided, so it is always an empty byte string of size 0)
    HashFunc.Func(NULL, 0, EncodedMessage+EMPos);
    EMPos+=HashFunc.Size;

    // Zero Padding (Since we use calloc, there is no need to set bytes here.)
    EMPos+=ModSize-PSize-(2*HashFunc.Size)-2;

    // 0x01 byte (after Zero Padding)
    EncodedMessage[EMPos++] = 1;

    // The rest of EncodedMessage is the message bytes.
    for (size_t i = 0; i < PSize; i++)
        EncodedMessage[EMPos++] = Plaintext[i];

    // Generate a mask for the entire DataBlock
    uint8_t* DBMask = malloc(ModSize-HashFunc.Size-1);
    if (DBMask == NULL)
    {
        free(EncodedMessage);
        return malloc_error;
    }
    rsa_mgf1(IV, HashFunc.Size, ModSize-HashFunc.Size-1, HashFunc, DBMask);

    // Xor DBMask with the DB section of EncodedMessage
    size_t DBMaskSize = 0;
    for (EMPos = HashFunc.Size+1; EMPos < ModSize; EMPos++)
        EncodedMessage[EMPos] ^= DBMask[DBMaskSize++];
    free(DBMask);

    //? SeedBlock
    // Generate a mask for the the SeedBlock in EncodedMessage
    uint8_t* SeedMask = malloc(HashFunc.Size);
    if (SeedMask == NULL)
    {
        free(EncodedMessage);
        return malloc_error;
    }
    // mgf1 takes data from the entirety of the Masked DB in EncodedMessage.
    rsa_mgf1(EncodedMessage+HashFunc.Size+1, DBMaskSize, HashFunc.Size, HashFunc, SeedMask);

    // Xor SeedMask with the Seed, save result in corresponding SeedBlock in EncodedMessage
    for (size_t i = 0; i < HashFunc.Size; i++)
        EncodedMessage[1+i] = IV[i] ^ SeedMask[i];
    free(SeedMask);

    //? RSA
    // Encrypt EncodedMessage with RSA. Save result into RetArr (allocated here)
    rsa_raw(EncodedMessage, ModSize, PubKey, RetArr);
    free(EncodedMessage);

    //! Testing needed, should work
    return success;
}

//^ Priority: 1
//! Use RSA_Encrypt for testing purposes
// decrypt Ciphertext -> Plaintext with RSA-OAEP
ErrorCode rsa_oaep_dec();

//^ Priority: 3
// Sign Text and return Tag (Tag == Hash of Text + Encrypted with Private)
//! Might be subject to change
ErrorCode rsa_sign();

// RSA encrypt primitive is the mpz_t function with mod powers
// RSA decrypt primitive is the mpz_t function with mod powers
// RSA encrypt & decrypt are also identical
// RSA sign primitive is RSA encrypt primitive with PrivateKey [Verifies that the message came from the private key]
// RSA verify primitive is RSA decrypt primitive with PublicKey (and check)

//^ Priority: 3
// Verify Text & Tag (Sign & Verify prevent Text from being modified: Hash can only be true if Text is same | Hash can only be encrypted by Private) [verifies both]
ErrorCode rsa_verify();

//? Private functions

// Add note: raw rsa encryption and decryption are identical but with different keys
static ErrorCode rsa_raw(uint8_t* Arr, size_t Size, RSAKey Key, ByteArr* RetArr)
{
    // Imports Arr into EncodedNum (as a number representation)
    mpz_t EncodedNum;
    mpz_init(EncodedNum);
    mpz_import(EncodedNum, Size, 1, 1, 1, 0, Arr);

    // Encrypts EncodedNum according to raw RSA
    mpz_powm(EncodedNum, EncodedNum, Key.Exp, Key.Mod);

    // Exports EncodedNum (encrypted) into RetArr
    RetArr->Arr = mpz_export(NULL, &RetArr->Size, 1, 1, 1, 0, EncodedNum);
    if (RetArr->Arr == NULL)
        return malloc_error;
    mpz_clear(EncodedNum);
    return success;
}

static ErrorCode rsa_mgf1(const uint8_t* Seed, size_t SeedSize, size_t RetSize, const HashParam HashFunc, uint8_t* RetArr)
{
    // 2^32 * HashFunc.HashSize
    if (RetSize > (4294967296)*HashFunc.Size)
        return length_error;

    uint8_t* SeedTemp = malloc(SeedSize+4);
    uint8_t* HashTemp = malloc(HashFunc.Size);
    if (SeedTemp == NULL || HashTemp == NULL)
    {
        free(SeedTemp);
        free(HashTemp);
        return malloc_error;
    }

    // Fill SeedTemp data from Seed
    for (size_t i = 0; i < SeedSize; i++)
        SeedTemp[i] = Seed[i];

    // Run until minimum number of rounds to fill the entirety of RetArr
    for (uint32_t i = 0; i <= RetSize; i+=HashFunc.Size)
    {
        //* Converts i (4 bytes) into MSB, and stores the result in the last 4 bytes of the SeedTemp array.
        for (int j = 0; j < 4; j++)
            SeedTemp[SeedSize + j] = ((i/HashFunc.Size) >> ((3-j)*8)) & 0xFF;

        // Hash(Seed || MSB(round, 4 bytes));
        ErrorCode TempError = HashFunc.Func(SeedTemp, SeedSize+4, HashTemp);
        if (TempError != success)
        {
            free(SeedTemp);
            free(HashTemp);
            return TempError;
        }
        
        //* Store result into RetArr (accounting for possible cutoff).
        if (i+HashFunc.Size > RetSize)
        {
            // Final (non HashSize divisible) Run
            for (size_t j = 0; j < (RetSize % HashFunc.Size); j++)
            {
                RetArr[i+j] = HashTemp[j];
            }
        }
        else
        {
            // Normal run
            for (size_t j = 0; j < HashFunc.Size; j++)
                RetArr[i+j] = HashTemp[j];
        }
    }
    free(SeedTemp);
    free(HashTemp);

    return success;
}