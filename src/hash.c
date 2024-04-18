#include "../include/hash.h"

//* Byte = most significant bit first
//* Word = 32-bit collection of 4 bytes, 
//*     LEAST SIGNIFICANT FIRST (This is how C stores uint32_t's. No change needed)

#define F(X,Y,Z) (((X) & (Y)) | (~(X) & (Z)))
#define G(X,Y,Z) (((X) & (Z)) | ((Y) & ~(Z)))
#define H(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define I(X,Y,Z) ((Y) ^ ((X) | ~(Z)))
#define Rot(X,Y) (((uint32_t) (X) << (Y)) | ((uint32_t) (X) >> (32 - (Y))))

const uint32_t T[64] = 
{
    0XD76AA478, 0XE8C7B756, 0X242070DB, 0XC1BDCEEE, 
    0XF57C0FAF, 0X4787C62A, 0XA8304613, 0XFD469501, 
    0X698098D8, 0X8B44F7AF, 0XFFFF5BB1, 0X895CD7BE, 
    0X6B901122, 0XFD987193, 0XA679438E, 0X49B40821, 
    0XF61E2562, 0XC040B340, 0X265E5A51, 0XE9B6C7AA, 
    0XD62F105D, 0X02441453, 0XD8A1E681, 0XE7D3FBC8, 
    0X21E1CDE6, 0XC33707D6, 0XF4D50D87, 0X455A14ED, 
    0XA9E3E905, 0XFCEFA3F8, 0X676F02D9, 0X8D2A4C8A, 
    0XFFFA3942, 0X8771F681, 0X6D9D6122, 0XFDE5380C, 
    0XA4BEEA44, 0X4BDECFA9, 0XF6BB4B60, 0XBEBFBC70, 
    0X289B7EC6, 0XEAA127FA, 0XD4EF3085, 0X04881D05, 
    0XD9D4D039, 0XE6DB99E5, 0X1FA27CF8, 0XC4AC5665, 
    0XF4292244, 0X432AFF97, 0XAB9423A7, 0XFC93A039, 
    0X655B59C3, 0X8F0CCC92, 0XFFEFF47D, 0X85845DD1, 
    0X6FA87E4F, 0XFE2CE6E0, 0XA3014314, 0X4E0811A1, 
    0XF7537E82, 0XBD3AF235, 0X2AD7D2BB, 0XEB86D391
};

//! Needs error detection, Needs entire revise tbh
ErrorCode hash_md5(void* Data, size_t Size, uint8_t* RetArr)
{
    //? Calculate and assign variables.

    uint8_t Pad = (120 - (Size % 64)) % 64;
    uint8_t* NewData  = (uint8_t *) calloc((Size + Pad + 8), sizeof(uint8_t));
    uint32_t* NewWord = (uint32_t*) NewData;

    //? Create a copy of the data to modify.
{
    size_t i;
    for (i = 0; i < Size; i++)
    {
        NewData[i] = ((uint8_t *) Data)[i];
    }
    NewData[i] = 0x80;
    i++;
}
    //? Append Size (before padding)

    // Append the size of the original Data (in bits) as two 32-bit words (low order first).
    NewWord[(Size+Pad+0) >> 2] = (uint32_t) ((Size * 8) & 0xFFFFFFFF);
    NewWord[(Size+Pad+4) >> 2] = (uint32_t) ((Size * 8) >> 32);

    //? Calculate the Hash

    //! If I change ABCD to State[4], there might be code Size optimization to be had.
    // Beginning values for (A, B, C, D)
    uint32_t A = 0x67452301;
    uint32_t B = 0xefcdab89;
    uint32_t C = 0x98badcfe;
    uint32_t D = 0x10325476;

   for (size_t i = 0; i < (Size+Pad+8)/64; i++)
   {
        uint32_t X[16];
        for (int j = 0; j < 16; j++)
        {
            X[j] = NewWord[i*16+j];
        }
        uint32_t AA = A;
        uint32_t BB = B;
        uint32_t CC = C;
        uint32_t DD = D;

        // Round 1
        A = B + (Rot((A + F(B,C,D) + X[0] + T[0]), 7));
        D = A + (Rot((D + F(A,B,C) + X[1] + T[1]), 12));
        C = D + (Rot((C + F(D,A,B) + X[2] + T[2]), 17));
        B = C + (Rot((B + F(C,D,A) + X[3] + T[3]), 22));
        A = B + (Rot((A + F(B,C,D) + X[4] + T[4]), 7));
        D = A + (Rot((D + F(A,B,C) + X[5] + T[5]), 12));
        C = D + (Rot((C + F(D,A,B) + X[6] + T[6]), 17));
        B = C + (Rot((B + F(C,D,A) + X[7] + T[7]), 22));
        A = B + (Rot((A + F(B,C,D) + X[8] + T[8]), 7));
        D = A + (Rot((D + F(A,B,C) + X[9] + T[9]), 12));
        C = D + (Rot((C + F(D,A,B) + X[10] + T[10]), 17));
        B = C + (Rot((B + F(C,D,A) + X[11] + T[11]), 22));
        A = B + (Rot((A + F(B,C,D) + X[12] + T[12]), 7));
        D = A + (Rot((D + F(A,B,C) + X[13] + T[13]), 12));
        C = D + (Rot((C + F(D,A,B) + X[14] + T[14]), 17));
        B = C + (Rot((B + F(C,D,A) + X[15] + T[15]), 22));

        // Round 2
        A = B + (Rot((A + G(B,C,D) + X[1] + T[16]), 5));
        D = A + (Rot((D + G(A,B,C) + X[6] + T[17]), 9));
        C = D + (Rot((C + G(D,A,B) + X[11] + T[18]), 14));
        B = C + (Rot((B + G(C,D,A) + X[0] + T[19]), 20));
        A = B + (Rot((A + G(B,C,D) + X[5] + T[20]), 5));
        D = A + (Rot((D + G(A,B,C) + X[10] + T[21]), 9));
        C = D + (Rot((C + G(D,A,B) + X[15] + T[22]), 14));
        B = C + (Rot((B + G(C,D,A) + X[4] + T[23]), 20));
        A = B + (Rot((A + G(B,C,D) + X[9] + T[24]), 5));
        D = A + (Rot((D + G(A,B,C) + X[14] + T[25]), 9));
        C = D + (Rot((C + G(D,A,B) + X[3] + T[26]), 14));
        B = C + (Rot((B + G(C,D,A) + X[8] + T[27]), 20));
        A = B + (Rot((A + G(B,C,D) + X[13] + T[28]), 5));
        D = A + (Rot((D + G(A,B,C) + X[2] + T[29]), 9));
        C = D + (Rot((C + G(D,A,B) + X[7] + T[30]), 14));
        B = C + (Rot((B + G(C,D,A) + X[12] + T[31]), 20));

        // Round 3
        A = B + (Rot((A + H(B,C,D) + X[5] + T[32]), 4));
        D = A + (Rot((D + H(A,B,C) + X[8] + T[33]), 11));
        C = D + (Rot((C + H(D,A,B) + X[11] + T[34]), 16));
        B = C + (Rot((B + H(C,D,A) + X[14] + T[35]), 23));
        A = B + (Rot((A + H(B,C,D) + X[1] + T[36]), 4));
        D = A + (Rot((D + H(A,B,C) + X[4] + T[37]), 11));
        C = D + (Rot((C + H(D,A,B) + X[7] + T[38]), 16));
        B = C + (Rot((B + H(C,D,A) + X[10] + T[39]), 23));
        A = B + (Rot((A + H(B,C,D) + X[13] + T[40]), 4));
        D = A + (Rot((D + H(A,B,C) + X[0] + T[41]), 11));
        C = D + (Rot((C + H(D,A,B) + X[3] + T[42]), 16));
        B = C + (Rot((B + H(C,D,A) + X[6] + T[43]), 23));
        A = B + (Rot((A + H(B,C,D) + X[9] + T[44]), 4));
        D = A + (Rot((D + H(A,B,C) + X[12] + T[45]), 11));
        C = D + (Rot((C + H(D,A,B) + X[15] + T[46]), 16));
        B = C + (Rot((B + H(C,D,A) + X[2] + T[47]), 23));

        // Round 4
        A = B + (Rot((A + I(B,C,D) + X[0] + T[48]), 6));
        D = A + (Rot((D + I(A,B,C) + X[7] + T[49]), 10));
        C = D + (Rot((C + I(D,A,B) + X[14] + T[50]), 15));
        B = C + (Rot((B + I(C,D,A) + X[5] + T[51]), 21));
        A = B + (Rot((A + I(B,C,D) + X[12] + T[52]), 6));
        D = A + (Rot((D + I(A,B,C) + X[3] + T[53]), 10));
        C = D + (Rot((C + I(D,A,B) + X[10] + T[54]), 15));
        B = C + (Rot((B + I(C,D,A) + X[1] + T[55]), 21));
        A = B + (Rot((A + I(B,C,D) + X[8] + T[56]), 6));
        D = A + (Rot((D + I(A,B,C) + X[15] + T[57]), 10));
        C = D + (Rot((C + I(D,A,B) + X[6] + T[58]), 15));
        B = C + (Rot((B + I(C,D,A) + X[13] + T[59]), 21));
        A = B + (Rot((A + I(B,C,D) + X[4] + T[60]), 6));
        D = A + (Rot((D + I(A,B,C) + X[11] + T[61]), 10));
        C = D + (Rot((C + I(D,A,B) + X[2] + T[62]), 15));
        B = C + (Rot((B + I(C,D,A) + X[9] + T[63]), 21));

        A = A + AA;
        B = B + BB;
        C = C + CC;
        D = D + DD;
   }

    //* TempHash will be 16 bytes (4 words). Set as (ABCD) with A being the lowest order byte
    uint8_t TempHash[16];
    // Treat TempHash as if it is an array of 4 words, instead of 16 bytes.
    //! A majority of this program is probably little-endian dependant (especially here)
    ((uint32_t*) RetArr)[0] = A;
    ((uint32_t*) RetArr)[1] = B;
    ((uint32_t*) RetArr)[2] = C;
    ((uint32_t*) RetArr)[3] = D;

    // Free the Malloc
    free(NewData);
    return 0;
}