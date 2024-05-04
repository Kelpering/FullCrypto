#ifndef RSA_PRIVATE_H
#define RSA_PRIVATE_H

// /// @brief Raw RSA encrypt (c = (m^d)mod n)
// /// @param Plaintext mpz_t Plaintext to encrypt.
// /// @param PubKey RSAKey to encrypt with.
// /// @note rsa_encrypt and rsa_decrypt are both identical but are separated to differentiate between encrypting and decrypting.
// #define RSA_ENCRYPT(Plaintext, PubKey) mpz_powm(Plaintext, Plaintext, PubKey.Exp, PubKey.Mod)

// /// @brief Raw RSA decrypt (m = (c^e)mod n)
// /// @param Ciphertext mpz_t Ciphertext to decrypt.
// /// @param PrivKey RSAKey to decrypt with.
// /// @note rsa_encrypt and rsa_decrypt are both identical but are separated to differentiate between encrypting and decrypting.
// #define RSA_DECRYPT(Ciphertext, PrivKey) mpz_powm(Ciphertext, Ciphertext, PrivKey.Exp, PrivKey.Mod)

// // Description needed
// static ErrorCode rsa_encode(uint8_t* Arr, size_t Size, mpz_t RetNum);

// // Description needed
// static ErrorCode rsa_decode(mpz_t Num, ByteArr* RetArr);

static ErrorCode rsa_raw(uint8_t* Arr, size_t Size, RSAKey Key, ByteArr* RetArr);

// Description needed
static ErrorCode rsa_mgf1(const uint8_t* Seed, size_t SeedSize, size_t RetSize, const HashParam HashFunc, uint8_t* RetArr);

#endif // RSA_PRIVATE_H