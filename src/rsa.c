#include "../include/rsa.h"
#include "../include/rsa_private.h"

//? Ordered by priority
//* encode/decode
//* encrypt/decrypt (raw, macro)
//^ mgf_1
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
ErrorCode rsa_oaep_enc(const uint8_t* Plaintext, size_t PSize, const uint8_t* IV, RSAKey PubKey, ByteArr* RetArr)
{
    // Directly convert Plaintext num into Ciphertext num

    // lHash = MD5("\0")
    // PS = ((mpz_sizeinbase(PubKey.Mod,2) + 7) / 8) - ((mpz_sizeinbase(Num,2) + 7) / 8) - 32 - 2 0 Octets
    // mLen and kLen are used pretty often, also PS is quite large (unknown if true)

    // DB = lHash || PS || 0x01 || Message num

    // seed = 16 bytes of random
    // dbMask = MGF1(seed, PubKey.Mod-17)
    // MaskedDb = dbMask ^ DB

    // SeedMask = MGF1(maskedDB, 16)
    // MaskedSeed = Seed ^ SeedMask

    // EM = 0 || MaskedSeed || MaskedDB

    // All of the above seem to work MUCH better on bytes, not mpz_t.
    // Make this function take the bytearrs, then use those

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

//^ Priority: 1
// Encodes a variable byte array of any size into an mpz_t (which all previous functions require)
ErrorCode rsa_encode(uint8_t* Arr, size_t Size, mpz_t RetNum)
{
    // Assume RetNum is not initialized
    mpz_init(RetNum);
    mpz_import(RetNum, Size, 1, 1, 1, 0, Arr);

    return success;
}

//^ Priority: 1
// Decodes an mpz_t into a variable byte array (ByteArr)
ErrorCode rsa_decode(mpz_t Num, ByteArr* RetArr)
{
    // mpz_export allocates arr of Size bytes, MSB.
    // We then deallocate mpz_t
    RetArr->Arr = mpz_export(NULL, &RetArr->Size, 1, 1, 1, 0, Num);
    if (RetArr->Arr == NULL)
        return malloc_error;
    mpz_clear(Num);

    return success;
}

ErrorCode rsa_mgf1(uint8_t* Seed, size_t SeedSize, size_t RetSize, HashParam HashFunc, uint8_t* RetArr)
{
    // HashFunc will allow users to change which hash function they want to use.

    // Mask Seed (Byte string)
    // mask length (len of Output for MGF1)
    // HashOutLen depends on the hash (MD5 for now, 16)
    // 2^32 * HashOutLen
    // Length check

    //* From 0 -> ceil(masklen/16 [hLen]) - 1 (i)
        //* Can probably simplify this because masklen will probably be a multiple of 16
        //* Or use (>> 4)
    //* Take i, convert into 4 byte word (same as decode) = C
    //* T = T || MD5(Seed || C)

    //* Return leading RetSize bytes of T as the mask

    //* (2^32 * HashFunc.HashSize)

    //! Lack of understanding is causing me to mess up here. List all steps and goals of this function.


    if (RetSize > (4294967296)*HashFunc.HashSize)
        return length_error;

    //! TEST REQUIRED

    uint8_t* Temp = malloc(HashFunc.HashSize);

    uint8_t* SeedTemp = malloc(SeedSize + 4);
    if (SeedTemp == NULL)
        return malloc_error;
    
    // Fill SeedTemp with Seed
    for (int i = 0; i < SeedSize; i++)
        SeedTemp[i] = Seed[i];        

    //! Pretty sure this entire section fails in multiple ways
    //! Test and rewrite with this as a general sense of what it's doing.
    for (uint32_t i = 0; i < (RetSize-RetSize%HashFunc.HashSize)>>4 - 1; i++)
    {
        // concatenates i (4 bytes) as MSB to SeedTemp
        for (int j = 0; j < 4; j++)
            SeedTemp[SeedSize + j] = (i >> ((3-j)*8)) & 0xFF;

        // Hashes SeedTemp into Temp, then assigns that to RetArr sequentially
        ErrorCode TempError = HashFunc.HashFunc(SeedTemp, SeedSize+4, Temp);
        if (TempError != success)
            return TempError;
        
        if (i*HashFunc.HashSize < RetSize)
            for (int j = 0; j < HashFunc.HashSize; j++)
                RetArr[i*HashFunc.HashSize+j] = Temp[j];
        else
            for (int j = 0; j < HashFunc.HashSize - RetSize%HashFunc.HashSize; j++)
                RetArr[i*HashFunc.HashSize+j] = Temp[j];
        
    }

    return success;
}