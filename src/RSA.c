#include "../include/RSA.h"
#include "../include/MD5.h"

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

void GenerateKeyPair(const uint64_t Seed, RSAKey Public, RSAKey Private)
{
    // 4096-bit
    // Generate all required values for a keypair, save them to the keys
}

void RSA_Encrypt(mpz_t Plaintext, const RSAKey Public)
{
    mpz_powm_ui(Plaintext, Plaintext, Public.Exp, Public.Mod);
}

void RSA_Decrypt(mpz_t Ciphertext, const RSAKey Private)
{
    mpz_powm_ui(Ciphertext, Ciphertext, Private.Exp, Private.Mod);
}

void RSA_Sign(const mpz_t Message, mpz_t Sign, const RSAKey Private)
{
    // Sign = RSAEncrypt(Hash(Text), Private)
    // This means the hash can be decrypted via the public key
    // The hash prevents modification without detection
    // Directly change mpz_t Sign
    //* Convert mpz_t Message into Array via Decode (temporarily) 
    ByteArr TempDecode = DecodeArray(Message);
    uint8_t Hash[16] = {0};

}

bool RSA_Verify(const mpz_t Text, const mpz_t Sign, const RSAKey Public)
{
    // Sign = RSADecrypt(Sign, Public)  (Proves private encrypted it)
    // NewSign = Hash(Text)       (Hash Text)
    // Return (Sign == NewSign)         If Ciphertext is altered, hash wont match. If Sign is altered, RSA decrypt wont match
}

// Function: void mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op)
// Set rop from an array of word data at op.

// The parameters specify the format of the data. count many words are read, each size bytes. order can be 1 for most significant word first or -1 
// for least significant first. Within each word endian can be 1 for most significant byte first, -1 for least significant first, or 0 for the native 
// endianness of the host CPU. The most significant nails bits of each word are skipped, this can be 0 to use the full words.



mpz_t EncodeArray(uint8_t* Array, size_t Size)
{

}

ByteArr DecodeArray(mpz_t Num)
{
    // type DecodeArray(mpz_t Number)
// Return (decide later) Byte array that contains the mpz_t number decoded
// Depending on how the number has to be encoded/decoded, this might just be the equivalent GMP function
}

