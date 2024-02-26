#pragma once
#include <stdint.h>
#include <stdlib.h>


//? Directives and Arrays

/// @brief Cyclically rotates x by shift bits.
/// @param x The value to rotate (8-bit)
/// @param shift Number of bits to shift by.
#define ROTL8(x, shift) ((x<<shift) | (x >> (8 - shift)))

/// @brief Accesses byte array X as if it were a bit array.
/// @param x A uint8_t[16].
/// @param bit The bit to access, from 0-127.
#define BitArr128(x, bit) ((x[bit>>3] >> (7-(bit%8))) & 1)

/// @brief SBox array to allow for much faster encryption.
static uint8_t SBox[256];

/// @brief Inverse of SBox array, for decryption.
static uint8_t InvSBox[256];


//? Key functions

/// @brief Xors the current Expanded round Key to the State directly.
/// @param State The 16-byte array, directly altered by function.
/// @param EKey The current Expanded round Key to XOR.
static void AddRoundKey(uint8_t* State, const uint8_t* EKey);

/// @brief Performs repeat transformations on Key to produce an Expanded round Key for each round.
/// @param Key The Key input into both Encrypt and Decrypt functions.
/// @returns A pointer to the Expanded round Key. Must be freed after use.
/// @warning Returns an allocated array full of key information. Must be overwritten first, then freed.
static uint8_t* KeyExpansion256(const uint8_t* Key);

/// @brief Rotates a 4-byte word by each byte, to the left.
/// @param Word 4-byte array (includes uint32_t) to alter.
static void RotWord(uint8_t* Word);

/// @brief Applies SBox[] to each Byte in a 4-byte word.
/// @param Word 4-byte array (includes uint32_t) to alter.
static void SubWord(uint8_t* Word);


//? Encryption functions

/// @brief Shifts each row of State left by an amount equal to the row number.
/// @param State A 16-byte array, interpreted as a 4x4 byte array.
static void ShiftRows(uint8_t* State);

/// @brief Applies SBox[] to each byte of state.
/// @param State A 16-byte array.
static void SubBytes(uint8_t* State);

/// @brief Multiplies and transforms state, via matrix multiplication, to each column.
/// @param State A 16-byte array, interpreted as a 4x4 byte array.
static void MixColumns(uint8_t* State);


//? Decryption functions

/// @brief Shifts each row of State right by an amount equal to the row number (Inverse of ShiftRows).
/// @param State A 16-byte array, interpreted as a 4x4 byte array.
static void InvShiftRows(uint8_t* State);

/// @brief Applies InvSBox[] to each byte of state (Inverse of SubBytes).
/// @param State A 16-byte array.
static void InvSubBytes(uint8_t* State);

/// @brief Multiplies and transforms state, via matrix multiplication, to each column (Inverse of MixColumns).
/// @param State A 16-byte array, interpreted as a 4x4 byte array.
static void InvMixColumns(uint8_t* State);


//* Universal functions

/// @brief Multiplies two numbers within the Galois Field GF(2^8).
/// @returns X*Y within GF(2^8).
static uint8_t GMul(uint8_t x, uint8_t y);

/// @brief Generates a number for Byte that, when multiplied within the Galois Field GF(2^8), returns 1.
/// @returns The Multiplicative Inverse of Byte.
static uint8_t GInv(uint8_t Byte);

/// @brief Increments the last 32 bits of a 128-bit Block (as if it were a 128-bit number).
/// @param Block A uint8_t[16] representing a 128-bit number.
static void GInc32(uint8_t* Block);

/// @brief Returns X*Y in GF(2^128) into Result.
/// @param X A uint8_t[16] that represents a 128-bit number.
/// @param Y A uint8_t[16] that represents a 128-bit number.
/// @param Result The product, can be X, Y, or any other uint8_t[16].
static void GBlockMul(const uint8_t* X, const uint8_t* Y, uint8_t* Result);

/// @brief Performs the GHash on Block, of Size bytes. If Size is not a multiple of 16, 0's will be padded to the end.
/// @param H The Hash Subkey, internal to GCM.
/// @param Block A uint8_t[] of any size. Contains the data to hash.
/// @param Size The size of the Block, in bytes.
/// @param Output A uint8_t[16] to write the final hash to.
/// @note Due to how the GHash function works, the final hash block can be put into Output to "concatenate" the byte strings (on full 16-byte blocks). Ex: GHash(A+B->O) = GHash(B->GHash(A))
static void GHash(const uint8_t* H, const uint8_t* Block, size_t Size, uint8_t* Output);

/// @brief Encrypts (and decrypts) Plaintext.
/// @param Plaintext The plaintext of any size, overwritten by result (Ciphertext).
/// @param Size The Size of Plaintext (and Ciphertext) in bytes.
/// @param Key The key to encrypt Plaintext and decrypt Ciphertext with. 
/// @param ICB The Initial Counter Block (IV).
/// @note This function works forwards and backwards. Plaintext is encrypted on the first run, and decrypted on the second (identical) run.
static void GCTR(uint8_t* Plaintext, size_t Size, const uint8_t* Key, const uint8_t* ICB);

/// @brief Applies SBox[] to a Byte, but via calculations instead of an array.
/// @returns SBox[Byte].
static uint8_t SBoxFunc(uint8_t Byte);

/// @brief Applies InvSBox[] to a Byte, but via calculations instead of an array.
/// @returns InvSBox[Byte].
static uint8_t InvSBoxFunc(uint8_t Byte);

/// @brief Initializes the internal "SBox" of AESEnc to allow for proper encryption.
void InitSBox();

/// @brief Initializes the internal "InvSBox" of AESDec to allow for proper decryption.
void InitInvSBox();