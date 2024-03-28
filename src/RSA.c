#include "../include/RSA.h"

// PKCS#1 apparently has an actual algorithm.
// Time to "reference" the algorithm

// Generate prime (Bit size 1024, or 2048 for 2048, or 4096 respectively)
//* Specifically, we might want to generate them together to allow for
//* A primality test and regenerating the primes.
//* GMP Random functions as well
//! GMP next prime might work here, but unknown if number isn't prime

// Multiply p & q to produce N (GMP)

// Generate Carmichael totient function
//* LCM(p-1, q-1) (mpz_lcm)
//* LCM = |A*B|/GCD(a,b)
// Might be GMP (mpz_gcd)
// Otherwise, euclidean algorithm for GCD with recursive
// GCD(x,y) = GCD(y, x%y)
// To GCD x,y: GCD (x, y%x). Assume y is greater than x here.
// This is recursive.

// Choose e so that 1 < e < carmichael & GCD(e,carhmichael) == 1 (coprime)
// Smaller e and smaller hamming weight good (number of 1 is number of hamming weight)

// d = e^-1 (mod carmichael)

// Public:  (n, e)
// Private: (d) (Discard p, q, carmichael)