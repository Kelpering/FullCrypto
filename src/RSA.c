#include "../include/RSA.h"

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