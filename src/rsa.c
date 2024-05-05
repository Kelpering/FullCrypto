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
ErrorCode rsa_generate_keypair(size_t BitSize, uint64_t Seed, RSAKey* Public, RSAKey* Private)
{
    //? Setup
    // Set Public exponent to be 65537 (for convenience & security)
    mpz_init_set_ui(Public->Exp, 65537);
    mpz_init(Public->Mod);
    mpz_init(Private->Exp);
    mpz_init(Private->Mod);

    // Initialize gmp random functions
    gmp_randstate_t RandState;
    gmp_randinit_mt(RandState);
    mpz_t SeedNum;
    mpz_init_set_ui(SeedNum, Seed);
    gmp_randseed(RandState, SeedNum);

    // Initialize Temporary variables.
    mpz_t P, Q, Temp;
    mpz_init(P);
    mpz_init(Q);
    mpz_init(Temp);

    //? Generate Primes
    while (1)
    {
        //? Generate P
        while (1)
        {
            mpz_urandomb(P, RandState, BitSize/2);
            mpz_setbit(P, BitSize/2 - 1);
            mpz_setbit(P, BitSize/2 - 1);
            mpz_nextprime(P, P);

            // Retry if P mod E == 1
            mpz_mod(Temp, P, Public->Exp);
            if (mpz_cmp_ui(Temp, 1) == 0)
                continue;
            else
                break;
        }

        //? Generate Q
        while (1)
        {
            mpz_urandomb(Q, RandState, BitSize/2);
            mpz_setbit(Q, BitSize/2 - 1);
            mpz_setbit(Q, BitSize/2 - 1);
            mpz_nextprime(Q, Q);

            // Retry if P mod E == 1
            mpz_mod(Temp, Q, Public->Exp);
            if (mpz_cmp_ui(Temp, 1) == 0)
                continue;
            else
                break;
        }

        // If P == Q, restart
        if (mpz_cmp(P, Q) == 0)
            continue;
        break;
    }
    gmp_randclear(RandState);
    // P & Q are verified primes at this point

    //? Generate D and N (Private exponent and modulus)
    // Generate Modulus (P*Q)
    mpz_mul(Public->Mod, P, Q);
    mpz_set(Private->Mod, Public->Mod);

    // Temp here is now the totient of N (p-1 * q-1)
    mpz_sub_ui(P, P, 1);
    mpz_sub_ui(Q, Q, 1);
    mpz_mul(Temp, P, Q);

    mpz_invert(Private->Exp, Public->Exp, Temp);

    // Clear allocated memory (GMP)
    mpz_clear(P);
    mpz_clear(Q);
    mpz_clear(Temp);
    return success;
}

void rsa_destroy_key(RSAKey Key)
{
    mpz_clear(Key.Exp);
    mpz_clear(Key.Mod);
    
    return;
}

//^ Priority: 1
//! Use RSA_Encrypt for testing purposes
// encrypt Plaintext -> Ciphertext with RSA-OAEP
ErrorCode rsa_oaep_enc(const uint8_t* Plaintext, size_t PSize, const uint8_t* IV, const RSAKey PubKey, const HashParam HashFunc, ByteArr* RetArr)
{
    //? Length checking and setup
    // Size of PubKey.Mod in bytes (k in RFC)
    ErrorCode TempError;
    size_t ModSize = (mpz_sizeinbase(PubKey.Mod, 2) + 7) >> 3;

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
    TempError = HashFunc.Func(NULL, 0, EncodedMessage+EMPos);
    if (TempError != success)
    {
        free(EncodedMessage);
        return TempError;
    }
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
    TempError = rsa_mgf1(IV, HashFunc.Size, ModSize-HashFunc.Size-1, HashFunc, DBMask);
    if (TempError != success)
    {
        free(EncodedMessage);
        return TempError;
    }

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
    TempError = rsa_mgf1(EncodedMessage+HashFunc.Size+1, DBMaskSize, HashFunc.Size, HashFunc, SeedMask);
    if (TempError != success)
    {
        free(EncodedMessage);
        return TempError;
    }

    // Xor SeedMask with the Seed, save result in corresponding SeedBlock in EncodedMessage
    for (size_t i = 0; i < HashFunc.Size; i++)
        EncodedMessage[1+i] = IV[i] ^ SeedMask[i];
    free(SeedMask);

    //? RSA
    // Encrypt EncodedMessage with RSA. Save result into RetArr (allocated here)
    TempError = rsa_raw(EncodedMessage, ModSize, PubKey, RetArr);
    free(EncodedMessage);

    if (TempError != success)
        free(RetArr->Arr);
    return TempError;
}

ErrorCode rsa_oaep_dec(const uint8_t* Ciphertext, size_t CSize, const RSAKey PrivKey, const HashParam HashFunc, ByteArr* RetArr)
{
    //? Length checking and setup
    // Size of PrivKey.Mod in bytes (k in RFC)
    ErrorCode TempError;
    size_t ModSize = (mpz_sizeinbase(PrivKey.Mod, 2) + 7) >> 3;

    // Length Check: Either CSize does not match ModSize, or ModSize is too small.
    if (CSize != ModSize || ModSize < (2*HashFunc.Size) + 2)
        return length_error;
    
    //? RSA decrypt and basic checks
    // mpz does not save the leading 0x00, so we add this in a new ByteArr
    ByteArr Temp;
    TempError = rsa_raw(Ciphertext, CSize, PrivKey, &Temp);
    if (TempError != success)
    {
        free(Temp.Arr);
        return TempError;
    }
    ByteArr EncodedMessage;
    EncodedMessage.Size = Temp.Size+1;
    EncodedMessage.Arr = malloc(EncodedMessage.Size);
    if (EncodedMessage.Arr == NULL)
    {
        free(Temp.Arr);
        return malloc_error;
    }

    // Accounts for missing 0
    for(size_t i = 0; i < Temp.Size; i++)
        EncodedMessage.Arr[i+1] = Temp.Arr[i];
    EncodedMessage.Arr[0] = 0x00;
    free(Temp.Arr);

    //? SeedBlock recovery
    // Generate a mask for the the SeedBlock in EncodedMessage
    uint8_t* SeedMask = malloc(HashFunc.Size);
    if (SeedMask == NULL)
    {
        free(EncodedMessage.Arr);
        return malloc_error;
    }
    // mgf1 takes data from the entirety of the Masked DB in EncodedMessage.
    TempError = rsa_mgf1(EncodedMessage.Arr+HashFunc.Size+1, EncodedMessage.Size-HashFunc.Size-1, HashFunc.Size, HashFunc, SeedMask);
    if (TempError != success)
    {
        free(SeedMask);
        free(EncodedMessage.Arr);
        return TempError;
    }

    // Xor SeedMask with the Seed in EncodedMessage. Use for further Seed requirements.
    for (size_t i = 0; i < HashFunc.Size; i++)
        EncodedMessage.Arr[i+1] ^= SeedMask[i];
    free(SeedMask);

    //? Data Block recovery (DB)
    // Generate a mask for the DataBlock in EncodedMessage
    uint8_t* DBMask = malloc(EncodedMessage.Size-HashFunc.Size-1);
    if (DBMask == NULL)
    {
        free(EncodedMessage.Arr);
        return malloc_error;
    }
    // mgf1 takes data from the SeedBlock that was just unmasked in the previous step
    TempError = rsa_mgf1(EncodedMessage.Arr+1, HashFunc.Size, EncodedMessage.Size-HashFunc.Size-1, HashFunc, DBMask);
    if (TempError != success)
    {
        free(DBMask);
        free(EncodedMessage.Arr);
        return TempError;
    }

    // Xor DBMask with the Data Block in EncodedMessage. Use as plaintext Data Block
    for (size_t i = 0; i < EncodedMessage.Size-HashFunc.Size-1; i++)
        EncodedMessage.Arr[i+HashFunc.Size+1] ^= DBMask[i];
    free(DBMask);

    // lHash (label Hash) which is a null byte string of size 0 hashed with HashFunc.
    uint8_t* lHash = malloc(HashFunc.Size);
    TempError = HashFunc.Func(NULL, 0, lHash);
    if (TempError != success)
    {
        free(lHash);
        free(EncodedMessage.Arr);
        return TempError;
    }

    // Check generated lHash against message lHash
    for (size_t i = 0; i < HashFunc.Size; i++)
        if (lHash[i] != EncodedMessage.Arr[i+HashFunc.Size+1])
        {
            free(lHash);
            free(EncodedMessage.Arr);
            return unknown_error;
        }
    free(lHash);

    // Finds end of Zero Padding (PS) section. If the PS ends with a byte other than 0x01, return error.
    size_t PSEnd;
    for (PSEnd = 1+(2*HashFunc.Size); PSEnd < EncodedMessage.Size; PSEnd++)
        if (EncodedMessage.Arr[PSEnd] != 0 && EncodedMessage.Arr[PSEnd] != 1)
        {
            free(EncodedMessage.Arr);
            return unknown_error;
        }
        else if (EncodedMessage.Arr[PSEnd] == 1)
            break;
    PSEnd++;

    // Allocates RetArr and sets it equal to the decrypted message.
    RetArr->Size = ModSize-PSEnd;
    RetArr->Arr = malloc(RetArr->Size);
    if (RetArr->Arr == NULL)
    {
        free(EncodedMessage.Arr);
        return malloc_error;
    }
    for (size_t i = 0, j = PSEnd; j < ModSize; i++,j++)
        RetArr->Arr[i] = EncodedMessage.Arr[j];
    free(EncodedMessage.Arr);

    return success;
}

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
ErrorCode rsa_raw(uint8_t* Arr, size_t Size, RSAKey Key, ByteArr* RetArr)
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