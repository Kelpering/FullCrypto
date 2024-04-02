#include "../include/RSA.h"

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

void GenerateKeyPair(uint64_t Seed, RSAKey Public, RSAKey Private)
{
    // 4096-bit
    // Generate all required values for a keypair, save them to newly allocated struct PrivateKey (Contains PublicKey)
}

void RSA_Encrypt(mpz_t Plaintext, RSAKey Public)
{
    mpz_powm_ui(Plaintext, Plaintext, Public.Exp, Public.Mod);
    //Is that it? If so, make this an inline to make this easier.
}

void RSA_Decrypt(mpz_t Ciphertext, RSAKey Private)
{
    mpz_powm_ui(Ciphertext, Ciphertext, Private.Exp, Private.Mod);
    //Is that it? If so, make this an inline to make this easier.
}



//! Signs here, do not need to be physically appended. Just send them along with eachother
//! Fix this in comments. Signs are to be allocated and produced (They are fixed size, but encrypted with rsa)

void RSA_Sign(mpz_t Ciphertext, RSAKey Private)
{
    // Ciphertext = Ciphertext ++ RSAEncrypt(Hash(Ciphertext), Private)
    // This means the hash can be decrypted via the public key
    // The hash prevents modification without detection
}

bool RSA_Verify(mpz_t Ciphertext, RSAKey Public)
{
    // Ciphertext = Ciphertext ++ Hash encrypted
    // Decouple Ciphertext and fixed size hash
    // Decrypt hash with Public exponent
    // Hash Ciphertext
    // Compare decrypted hash with self calculated hash
    // Return True/False
}

// type EncodeArray(uint8_t* Array, size_t Size);
// Return (decide later) mpz_t initialized to Array
// Depending on how the number has to be encoded/decoded, this might just be the equivalent GMP function

// type DecodeArray(mpz_t Number)
// Return (decide later) Byte array that contains the mpz_t number decoded
// Depending on how the number has to be encoded/decoded, this might just be the equivalent GMP function