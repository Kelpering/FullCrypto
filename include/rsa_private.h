#ifndef RSA_PRIVATE_H
#define RSA_PRIVATE_H

/// @brief Raw RSA encrypt (c = (m^d)mod n)
/// @param Plaintext mpz_t Plaintext to encrypt.
/// @param PubKey RSAKey to encrypt with.
/// @note rsa_encrypt and rsa_decrypt are both identical but are separated to differentiate between encrypting and decrypting.
#define rsa_encrypt(Plaintext, PubKey) mpz_powm(Plaintext, Plaintext, PubKey.Exp, PubKey.Mod)

/// @brief Raw RSA decrypt (m = (c^e)mod n)
/// @param Ciphertext mpz_t Ciphertext to decrypt.
/// @param PrivKey RSAKey to decrypt with.
/// @note rsa_encrypt and rsa_decrypt are both identical but are separated to differentiate between encrypting and decrypting.
#define rsa_decrypt(Ciphertext, PrivKey) mpz_powm(Ciphertext, Ciphertext, PrivKey.Exp, PrivKey.Mod)

#endif // RSA_PRIVATE_H