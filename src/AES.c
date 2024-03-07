#include "../include/AES.h"
#include "../include/AESPrivate.h"
#include <stdio.h>


//* Public functions
//? AES standard implementation

void AES_STD_Enc(uint8_t* Plaintext, const uint8_t* Key)
{
    //? If SBox has never been run before, initialize.
    if (SBox[0] != 0x63)
        InitSBox();

    //? Fill state sideways
    uint8_t State[16] = 
    {
        Plaintext[0], Plaintext[4], Plaintext[8], Plaintext[12],
        Plaintext[1], Plaintext[5], Plaintext[9], Plaintext[13],  
        Plaintext[2], Plaintext[6], Plaintext[10], Plaintext[14],  
        Plaintext[3], Plaintext[7], Plaintext[11], Plaintext[15]
    };

    //? Key expansion
    uint8_t* EKey = KeyExpansion256(Key);

    //? Xor first Key
    AddRoundKey(State, (EKey + 0*4));

    //? Rounds
    for (int i = 1; i < 14; i++)
    {
        SubBytes(State);
        ShiftRows(State);
        MixColumns(State);
        AddRoundKey(State, (EKey+(i*16)));
    }

    //? Final round without Mix Columns
    SubBytes(State);
    ShiftRows(State);
    AddRoundKey(State, (EKey+(14*16)));

    //? Clear and de-allocate Expanded Key
    for (int i = 0; i < 240; i++)
        EKey[i] = 0;
    free(EKey);

    //? Fill Data sideways
    Plaintext[0] = State[0];
    Plaintext[1] = State[4];
    Plaintext[2] = State[8];
    Plaintext[3] = State[12];
    Plaintext[4] = State[1];
    Plaintext[5] = State[5];
    Plaintext[6] = State[9];
    Plaintext[7] = State[13];
    Plaintext[8] = State[2];
    Plaintext[9] = State[6];
    Plaintext[10] = State[10];
    Plaintext[11] = State[14];
    Plaintext[12] = State[3];
    Plaintext[13] = State[7];
    Plaintext[14] = State[11];
    Plaintext[15] = State[15];

    return;
}

void AES_STD_Dec(uint8_t* Ciphertext, const uint8_t* Key)
{
    //? If InvSBox has never been run before, initialize.
    if (InvSBox[0] != 0x63)
        InitInvSBox();
    

    //? Fill state sideways
    uint8_t State[] = 
    {
        Ciphertext[0], Ciphertext[4], Ciphertext[8], Ciphertext[12],
        Ciphertext[1], Ciphertext[5], Ciphertext[9], Ciphertext[13],
        Ciphertext[2], Ciphertext[6], Ciphertext[10], Ciphertext[14],
        Ciphertext[3], Ciphertext[7], Ciphertext[11], Ciphertext[15]
    };

    //? Key expansion
    uint8_t* EKey = KeyExpansion256(Key);

    //? Xor last key
    AddRoundKey(State, (EKey + 14*16));

    //? Rounds in reverse
    for (int i = 14; i > 1; i--)
    {
        InvShiftRows(State);
        InvSubBytes(State);
        AddRoundKey(State, EKey+((i - 1)*16));
        InvMixColumns(State);
    }

    //? Last round without mix columns
    InvShiftRows(State);
    InvSubBytes(State);
    AddRoundKey(State, EKey + 0);
    
    //? Clear and de-allocate Expanded Key
    for (int i = 0; i < 240; i++)
        EKey[i] = 0;
    free(EKey);     //! Free here is SegFaulting somehow, although I am unsure why.

    //? Fill Data sideways
    Ciphertext[0] = State[0];
    Ciphertext[1] = State[4];
    Ciphertext[2] = State[8];
    Ciphertext[3] = State[12];
    Ciphertext[4] = State[1];
    Ciphertext[5] = State[5];
    Ciphertext[6] = State[9];
    Ciphertext[7] = State[13];
    Ciphertext[8] = State[2];
    Ciphertext[9] = State[6];
    Ciphertext[10] = State[10];
    Ciphertext[11] = State[14];
    Ciphertext[12] = State[3];
    Ciphertext[13] = State[7];
    Ciphertext[14] = State[11];
    Ciphertext[15] = State[15];

    return;
}


//? AES-ECB implementation

ByteArr AES_ECB_Enc(const uint8_t* Plaintext, size_t Size, const uint8_t* Key)
{
    if (Size == 0)
        return (ByteArr){NULL, 0};

    //? Declare variables & ByteArr struct
    ByteArr NewArr;
    uint8_t PadByte = 16 - (Size%16);
    NewArr.Size = Size + PadByte;
    NewArr.Arr = malloc(NewArr.Size);

    //? Copy over Plaintext to NewArr, then Pad to a multiple of 16
    for (size_t i = 0; i < Size; i++)
        NewArr.Arr[i] = Plaintext[i];
    for (size_t i = Size; i < NewArr.Size; i++)
        NewArr.Arr[i] = PadByte;

    //? Encrypt each 16 byte block.
    for (size_t i = 0; i < NewArr.Size; i+=16)
        AES_STD_Enc(NewArr.Arr + i, Key);

    //! Needs to be de-allocated
    return NewArr;
}

ByteArr AES_ECB_Dec(const uint8_t* Ciphertext, size_t Size, const uint8_t* Key)
{
    if (Size == 0 || Size%16 != 0)
        return (ByteArr){NULL, 0};

    //? Copy over Ciphertext
    uint8_t* Temp = malloc(Size);
    for (size_t i = 0; i < Size; i++)
        Temp[i] = Ciphertext[i];

    //? Decrypt Temp, 16 bytes at a time
    for (size_t i = 0; i < Size; i+=16)
        AES_STD_Dec(Temp + i, Key);

    //? Declare ByteArr Struct
    ByteArr NewArr;
    NewArr.Size = Size - Temp[Size-1];
    NewArr.Arr = malloc(NewArr.Size);

    //? Copy over Temp to ByteArr
    for (size_t i = 0; i < Size-Temp[Size-1]; i++)
        NewArr.Arr[i] = Temp[i];

    //? Free allocated Temp
    free (Temp);

    //! Needs to be de-allocated
    return NewArr;
}


//? AES-CBC implementation

ByteArr AES_CBC_Enc(const uint8_t* Plaintext, size_t Size, const uint8_t* Key, const uint8_t* IV)
{
    if (Size == 0)
        return (ByteArr){NULL, 0};

    ByteArr NewArr;
    uint8_t PadByte = 16 - (Size%16);
    NewArr.Size = PadByte + Size;
    NewArr.Arr = malloc(NewArr.Size);

    //? Fill NewArr with relevant data and padding.
    for (size_t i = 0; i < Size; i++)
        NewArr.Arr[i] = Plaintext[i];
    for (size_t i = Size; i < NewArr.Size; i++)
        NewArr.Arr[i] = PadByte;

    for (int i = 0; i < 16; i++)
        NewArr.Arr[i] ^= IV[i];
    for (size_t i = 0; i < NewArr.Size - 16; i+=16)
    {
        AES_STD_Enc(NewArr.Arr+i, Key);
        for (int j = 0; j < 16; j++)
            NewArr.Arr[i+16 + j] ^= NewArr.Arr[i + j];
    }
    // Final one without CBC function
    AES_STD_Enc(NewArr.Arr+NewArr.Size-16, Key);

    //! Needs to be de-allocated
    return NewArr;
}

ByteArr AES_CBC_Dec(const uint8_t* Ciphertext, size_t Size, const uint8_t* Key, const uint8_t* IV)
{
    if (Size == 0 || Size%16 != 0)
        return (ByteArr){NULL, 0};

    //? Copy over Ciphertext
    uint8_t* Temp = malloc(Size);
    for (size_t i = 0; i < Size; i++)
        Temp[i] = Ciphertext[i];

    //? Decrypt Temp, 16 bytes at a time
    for (size_t i = 0; i < Size; i+=16)
        AES_STD_Dec(Temp + i, Key);

    //? XOR each Ciphertext
    for (int i = 0; i < 16; i++)
        Temp[i] ^= IV[i];
    for (size_t i = 16; i < Size; i++)
        Temp[i] ^= Ciphertext[i-16];

    //? Declare ByteArr Struct
    ByteArr NewArr;
    NewArr.Size = Size - Temp[Size - 1];
    NewArr.Arr = malloc(NewArr.Size);

    //? Copy over Temp to ByteArr
    for (size_t i = 0; i < 32; i++)
        NewArr.Arr[i] = Temp[i];

    //? Free allocated Temp
    free(Temp);
    
    //! Needs to be de-allocated
    return NewArr;
}


//? AES-GCM implementation

uint8_t* AES_GCM_Enc(uint8_t* Plaintext, size_t PSize, const uint8_t* AAD, size_t ASize, const uint8_t* Key, const uint8_t* IV)
{
    //* Zero block (encrypted)
    uint8_t H[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    AES_STD_Enc(H, Key);

    //* J (IV) and JInc (GInc32(J))
    uint8_t J[16] =    {IV[0],IV[1],IV[2],IV[3],IV[4],IV[5],IV[6],IV[7],IV[8],IV[9],IV[10],IV[11],0,0,0,1};
    uint8_t JInc[16] = {IV[0],IV[1],IV[2],IV[3],IV[4],IV[5],IV[6],IV[7],IV[8],IV[9],IV[10],IV[11],0,0,0,2};

    //* Encrypt Plaintext here via GCTR. (Ciphertext)
    GCTR(Plaintext, PSize, Key, JInc);

    //* Initial hash block must be 0.
    uint8_t* Hash = calloc(16, 1);
    uint8_t LenBuf[16];
    size_t TempASize = ASize<<3;
    size_t TempPSize = PSize<<3;
    for(int i = 0; i < 8; i++)
    {
        LenBuf[i] = ((uint8_t*) &TempASize)[7-i];
        LenBuf[i+8] = ((uint8_t*) &TempPSize)[7-i];
    }

    //* Hash = GHash(AAD+0 Pad + PSize + 0 Pad + ASize[bits] + PSize[bits])
    //* Using GHash's last block as a first block works the same as concatenating the entire bit string.
    GHash(H, AAD, ASize, Hash);
    GHash(H, Plaintext, PSize, Hash);
    GHash(H, LenBuf, 16, Hash);

    //* Encrypt Hash with Key (Tag)
    GCTR(Hash, 16, Key, J);

    //! Needs to be de-allocated
    return Hash;
}

bool AES_GCM_Dec(const uint8_t* Ciphertext, size_t CSize, const uint8_t* AAD, size_t ASize, const uint8_t* Tag, const uint8_t* Key, const uint8_t* IV)
{
    //* Zero block (encrypted)
    uint8_t H[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    AES_STD_Enc(H, Key);

    //* J (IV) and JInc (GInc32(J))
    uint8_t J[16] =    {IV[0],IV[1],IV[2],IV[3],IV[4],IV[5],IV[6],IV[7],IV[8],IV[9],IV[10],IV[11],0,0,0,1};
    uint8_t JInc[16] = {IV[0],IV[1],IV[2],IV[3],IV[4],IV[5],IV[6],IV[7],IV[8],IV[9],IV[10],IV[11],0,0,0,2};

    //* Initial hash block must be 0.
    uint8_t* Hash = calloc(16, 1);
    uint8_t LenBuf[16];
    size_t TempASize = ASize<<3;
    size_t TempCSize = CSize<<3;
    for(int i = 0; i < 8; i++)
    {
        LenBuf[i] = ((uint8_t*) &TempASize)[7-i];
        LenBuf[i+8] = ((uint8_t*) &TempCSize)[7-i];
    }

    //* Hash = GHash(AAD+0 Pad + PSize + 0 Pad + ASize[bits] + PSize[bits])
    //* Using GHash's last block as a first block works the same as concatenating the entire bit string.
    GHash(H, AAD, ASize, Hash);
    GHash(H, Ciphertext, CSize, Hash);
    GHash(H, LenBuf, 16, Hash);

    //* Encrypt Hash with Key (Tag)
    GCTR(Hash, 16, Key, J);

    //* Validates (Ciphertext + AAD + Tag)
    bool IsValid = true;
    for (int i = 0; i < 16; i++)
        if (Tag[i] != Hash[i])
            IsValid = false;
    
    //* If invalid, return without modifying Ciphertext.
    if (IsValid == false)
        return false;
    
    //* Decipher Ciphertext and return true.
    GCTR(Ciphertext, CSize, Key, JInc);
    return true;
}


//? AES-GCM-SIV Implementation

uint8_t* AES_GCM_SIV_Enc(const uint8_t* Plaintext, size_t PSize, const uint8_t* AAD, size_t ASize, const uint8_t* Key, const uint8_t* IV)
{
    //* Allocate and initialize EncKey and AuthKey
    uint8_t EncKey[32];
    uint8_t AuthKey[16];
    SIVDeriveKeys(Key, IV, EncKey, AuthKey);

    //* mallloc Tag (initialized to 0).
    uint8_t* Tag = calloc(16, 1);

    //* Calculate Length Block for PolyVal later.
    uint64_t LenBlock[2] = {(ASize<<3), (PSize<<3)};
    
    //* Run PolyVal for AAD, Plaintext, LenBlock in sequence.
    PolyVal(AuthKey, AAD, ASize, Tag);
    PolyVal(AuthKey, Plaintext, PSize, Tag);
    PolyVal(AuthKey, LenBlock, 16, Tag);

    //* Xor first 12 bytes of Tag with IV
    for (int i = 0; i < 12; i++)
        Tag[i] ^= IV[i];

    //* Clear MSB of last byte in Tag
    Tag[15]  &= 0x7F;

    //* Produce final Tag version
    AES_STD_Enc(Tag, EncKey);

    //* Generates ICB for SivCtr
    uint8_t ICB[16] = {Tag[0], Tag[1], Tag[2], Tag[3], Tag[4], Tag[5], Tag[6], Tag[7], Tag[8], Tag[9], Tag[10], Tag[11], Tag[12], Tag[13], Tag[14], (Tag[15] | 0x80)};

    //* Encrypt Plaintext with SivCtr (Ciphertext)
    SivCTR(Plaintext, PSize, EncKey, ICB);

    //! Needs to be de-allocated
    return Tag;
}

bool AES_GCM_SIV_Dec(const uint8_t* Ciphertext, size_t CSize, const uint8_t* AAD, size_t ASize, const uint8_t* Tag, const uint8_t* Key, const uint8_t* IV)
{
    //* Allocate and initialize EncKey and AuthKey
    uint8_t EncKey[32];
    uint8_t AuthKey[16];
    SIVDeriveKeys(Key, IV, EncKey, AuthKey);

    //* Generates ICV for SivCtr
    uint8_t ICB[16] = {Tag[0], Tag[1], Tag[2], Tag[3], Tag[4], Tag[5], Tag[6], Tag[7], Tag[8], Tag[9], Tag[10], Tag[11], Tag[12], Tag[13], Tag[14], (Tag[15] | 0x80)};

    //* Malloc a Plaintext for indirect encryption, to prevent unauthenticated output.
    uint8_t* Plaintext = malloc(CSize);
    for(int i = 0; i < CSize; i++)
        Plaintext[i] = Ciphertext[i];

    //* Decrypt Plaintext with SivCtr
    SivCTR(Plaintext, CSize, EncKey, ICB);

    //* mallloc Tag (initialized to 0).
    uint8_t* PolyHash = calloc(16, 1);

    //* Calculate Length Block for PolyVal later.
    uint64_t LenBlock[2] = {(ASize<<3), (CSize<<3)};
    
    //* Run PolyVal for AAD, Plaintext, LenBlock in sequence.
    PolyVal(AuthKey, AAD, ASize, PolyHash);
    PolyVal(AuthKey, Plaintext, CSize, PolyHash);
    PolyVal(AuthKey, LenBlock, 16, PolyHash);

    //* Xor first 12 bytes of Tag with IV
    for (int i = 0; i < 12; i++)
        PolyHash[i] ^= IV[i];

    //* Clear MSB of last byte in Tag
    PolyHash[15]  &= 0x7F;

    //* Produce final Tag version
    AES_STD_Enc(PolyVal, EncKey);

    //* Validate Tag in constant time.
    bool IsInvalid = false;
    for (int i = 0; i < 16; i++)
        IsInvalid |= !(Tag == PolyHash);

    if (IsInvalid)
        return false;
    
    
    

    return false;
}


//? AES non-standard test functions

uint8_t* AES_KeyGen256(uint32_t Seed)
{
    srand(Seed);
    uint8_t* Key256 = malloc(32);

    for (int i = 0; i < 32; i++)
        Key256[i] = rand() % 256;
    return Key256;
}

uint8_t* AES_IVGen(uint32_t Seed, size_t Size)
{
    srand(Seed);
    uint8_t* IV = malloc(Size);

    for (int i = 0; i < Size; i++)
        IV[i] = rand() % 256;
    return IV;
}


//* Static functions
//? Key Functions

static void AddRoundKey(uint8_t* State, const uint8_t* EKey)
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            State[j*4+i] ^= EKey[i*4+j];
    return;
}

static uint8_t* KeyExpansion256(const uint8_t* Key)
{
    //? Malloc a 256-bit expanded key (constant size).
    uint32_t* EKey = malloc(240);

    //? First 8 words are the cipherkey, set as bytes.
    for (int i = 0; i < 8*4; i++)
        ((uint8_t*) EKey)[i] = Key[i];
    
    //? Generate 60 words (15 keys), first 4 set.
    //* RCON is the round constant, set to initial value of 1.
    uint8_t RCON = 1;
    for (int i = 8; i < (15*4); i++)
    {
        //* Prev is the last word generated.
        //* Prev is a seperate memory pointer from w[], to allow for memory manipulation without affecting previously generated keys.
        uint32_t Prev = *(EKey + i - 1);

        //? Transformes specific bytes in w[i].
        if (i % 8 == 0)
        {
            RotWord((uint8_t*) &Prev);
            SubWord((uint8_t*) &Prev);
            //* RCON is XOR'd directly because of Prev's endianness
            Prev ^= RCON;
            RCON = GMul(RCON, 0x02);
        }
        else if ((i+4)%8 == 0)
        {
            SubWord((uint8_t*) &Prev);
        }

        EKey[i] = EKey[i-8] ^ Prev;
    }

    //! Expanded key must be freed at the end of the AES run.
    return (uint8_t*) EKey;
}

static void RotWord(uint8_t* Word)
{
    uint8_t Temp = Word[0];
    Word[0] = Word[1];
    Word[1] = Word[2];
    Word[2] = Word[3];
    Word[3] = Temp;
    return;
}

static void SubWord(uint8_t* Word)
{
    Word[0] = SBox[Word[0]];
    Word[1] = SBox[Word[1]];
    Word[2] = SBox[Word[2]];
    Word[3] = SBox[Word[3]];
    return;
}


//? Encryption functions

static void ShiftRows(uint8_t* State)
{
    uint8_t Temp[16];
    for (int i = 0; i < 16; i++)
        Temp[i] = State[i];

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            State[i*4+j] = Temp[i*4+(j+i)%4];
    return;
}

static void SubBytes(uint8_t* State)
{
    for (int i = 0; i < 16; i++)
        State[i] = SBox[State[i]];
    return;
}

static void MixColumns(uint8_t* State)
{
    // Stores State while the column is being altered.
    uint8_t Temp[4];

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
            Temp[j] = State[j*4+i];

        State[0*4+i] = GMul(Temp[0], 0x02) ^ GMul(Temp[1], 0x03) ^ Temp[2] ^ Temp[3];
        State[1*4+i] = Temp[0] ^ GMul(Temp[1], 0x02) ^ GMul(Temp[2], 0x03) ^ Temp[3];
        State[2*4+i] = Temp[0] ^ Temp[1] ^ GMul(Temp[2], 0x02) ^ GMul(Temp[3], 0x03);
        State[3*4+i] = GMul(Temp[0], 0x03) ^ Temp[1] ^ Temp[2] ^ GMul(Temp[3], 0x02);
    }
    return;
}


//? Decryption functions

static void InvShiftRows(uint8_t* State)
{
    uint8_t Temp[16];
    for (int i = 0; i < 16; i++)
        Temp[i] = State[i];

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            State[i*4+(j+i)%4] = Temp[i*4+j];
    return;
}

static void InvSubBytes(uint8_t* State)
{
    for (int i = 0; i < 16; i++)
        State[i] = InvSBox[State[i]];
    return;
}

static void InvMixColumns(uint8_t* State)
{
    // Stores State while the column is being altered.
    uint8_t Temp[4];

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
            Temp[j] = State[j*4+i];

        State[0*4+i] = GMul(Temp[0], 0x0e) ^ GMul(Temp[1], 0x0b) ^ GMul(Temp[2], 0x0d) ^ GMul(Temp[3], 0x09);
        State[1*4+i] = GMul(Temp[0], 0x09) ^ GMul(Temp[1], 0x0e) ^ GMul(Temp[2], 0x0b) ^ GMul(Temp[3], 0x0d);
        State[2*4+i] = GMul(Temp[0], 0x0d) ^ GMul(Temp[1], 0x09) ^ GMul(Temp[2], 0x0e) ^ GMul(Temp[3], 0x0b);
        State[3*4+i] = GMul(Temp[0], 0x0b) ^ GMul(Temp[1], 0x0d) ^ GMul(Temp[2], 0x09) ^ GMul(Temp[3], 0x0e);
    }
    return;
}


//? Universal functions

static uint8_t GMul(uint8_t x, uint8_t y)
{
	uint8_t p = 0;
	uint8_t carry = 0;
    for (int i = 0; i < 8; i++)
	{
		//* If the first bit of Y is a 1, add x to p
		if (y&1)
            p ^= x;

        //* Set carry to 1 if x's 7th bit is 1
        carry = x & 0x80;
        
        x <<= 1;
        y >>= 1;

        //* If carry was set, add carry byte (0x1B)
        if (carry)
            x ^= 0x1B;
	}
    return p;
}

static uint8_t GInv(uint8_t Byte)
{
    //* Uses combinations of variables to multiply a by itself exactly 254 times.
    uint8_t b = GMul(Byte,Byte);
    uint8_t c = GMul(Byte,b);
            b = GMul(c,c);
            b = GMul(b,b);
            c = GMul(b,c);
            b = GMul(b,b);
            b = GMul(b,b);
            b = GMul(b,c);
            b = GMul(b,b);
            b = GMul(Byte,b);
    return GMul(b,b);
}

static void GInc32(uint8_t* Block)
{
    //* Reverses the endian of Block (as a 128-bit number) to allow for proper increment.
    uint32_t Temp = (Block[12] << 24) | (Block[13] << 16) | (Block[14] << 8) | Block[15];
    Temp++;
    Block[12] = (Temp >> 24) & 0xFF;
    Block[13] = (Temp >> 16) & 0xFF;
    Block[14] = (Temp >> 8) & 0xFF;
    Block[15] = Temp & 0xFF;
    return;
}

static void GBlockMul(const uint8_t* X, const uint8_t* Y, uint8_t* Result)
{
    //? Each block is a uint8_t[16] array, which represents a 128-bit number.
    uint8_t XCpy[16];
    uint8_t YCpy[16];
    for (int i = 0 ; i < 16; i++)
    {
        XCpy[i] = X[i];
        YCpy[i] = Y[i];
        Result[i] = 0;
    }

    for (int i = 0; i < 128; i++)
    {
        if (BitArr128(YCpy, i) == 1)
            for (int i = 0 ; i < 16; i++)
                Result[i] ^= XCpy[i];

        if (BitArr128(XCpy, 127) == 0)
        {            
            for (int i = 15; i > 0; i--)
                XCpy[i] = ((XCpy[i-1] & 1) << 7) | (XCpy[i] >> 1);
            XCpy[0] = (XCpy[0] >> 1);
        }
        else
        {
            for (int i = 15; i > 0; i--)
                XCpy[i] = ((XCpy[i-1] & 1) << 7) | (XCpy[i] >> 1);
            XCpy[0] = (XCpy[0] >> 1);
            
            //* V ^= R
            XCpy[0] ^= 0xE1;
        }
    }
    return;
}

static void GHash(const uint8_t* H, const uint8_t* Block, size_t Size, uint8_t* Output)
{   
    for (size_t i = 0; i < (Size>>4); i++)
    {
        for (int j = 0; j < 16; j++)
            Output[j] ^= Block[i*16+j];
        GBlockMul(Output, H, Output);
    }
    
    //* If final Block is incomplete, pad with 0's first
    if (Size % 16 != 0)
    {
        for (size_t j = 0; j < Size%16; j++)
            Output[j] ^= Block[Size-(Size%16)+j];
        for (int j = Size%16; j < 16; j++)
            Output[j] ^= 0;
        GBlockMul(Output, H, Output);
    }
    
    return;
}

static void GCTR(uint8_t* Plaintext, size_t Size, const uint8_t* Key, const uint8_t* ICB)
{
    //* Prevent Size overflow on last block.
    if (Size == 0)
        return;

    uint8_t Temp[16];
    uint8_t CB[16];
    for (int i = 0; i < 16; i++)
        CB[i] = ICB[i];
    
    //* Generate counter, Encrypt Counter, XOR plaintext block with counter.
   for (size_t i = 0; i < Size-(Size%16); i+=16)
   {
       for (size_t j = 0; j < 16; j++)
            Temp[j] = CB[j];
       AES_STD_Enc(Temp, Key);
       for (int j = 0; j < 16; j++)
            Plaintext[i+j] ^= Temp[j];
       GInc32(CB);
   } 
   //* Final Block (works on incomplete blocks)
   for (int j = 0; j < 16; j++)
       Temp[j] = CB[j];
   AES_STD_Enc(Temp, Key);
   for (size_t j = 0; j < Size%16; j++)
        Plaintext[Size-(Size%16)+j] ^= Temp[j];

    return;
}

static void SIVDeriveKeys(const uint8_t* MasterKey, const uint8_t* IV, uint8_t* EncKey, uint8_t* AuthKey)
{
    //! Remove / rework when tested
    //? MasterKey = 32-byte (AES-256)
    //? AuthKey = Empty 16-byte
    //? EncKey = Empty 32-byte
    //* Message Auth Key (MAK) & Message Enc Key (MEK)

    // 16 bytes (128-bit Tag)
    // MAK = AES(key = KeyGenKey, block = LE32(0) || nonce)[8bytes] ||
    //      AES(key=keyGenKey, block = LE32(1) || nonce)[8bytes]

    // 32 bytes (256-bit AES-Key)
    // MEK = AES(key = KeyGenKey, block = LE32(2) || nonce)[8bytes] ||
    //      AES(key = KeyGenKey, block = LE32(3) || nonce)[8bytes] ||
    //      AES(key = KeyGenKey, block = LE32(4) || nonce)[8bytes] ||
    //      AES(key = KeyGenKey, block = LE32(5) || nonce)[8bytes] ||


    //? AuthKey
    //* Generates TempAuthKey for AuthKey (16 bytes)
    uint8_t TempAuthKey[2][16];
    for (int i = 0; i < 2; i++)
    {
        //* Should be little endian
        ((uint32_t*) TempAuthKey[i])[0] = i;

        //* Rest is IV
        for (int j = 0; j < 12; j++)
            TempAuthKey[i][j+4] =  IV[j];
    }

    //* Encrypts each block in TempAuthKey
    for (int i = 0; i < 2; i++)
        AES_STD_Enc(TempAuthKey[i], MasterKey);

    //* Assigns the first 8 bytes of TempAuthKey[i] to AuthKey (16 bytes)
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < 8; j++)
            AuthKey[i*8+j] = TempAuthKey[i][j];


    //? EncKey
    //* Generates TempEncKey for EncKey (32 bytes)
    uint8_t TempEncKey[4][16];
    for (int i = 0; i < 4; i++)
    {
        //* Should be little endian
        ((uint32_t*) TempEncKey[i])[0] = i+2;

        //* Rest is IV
        for (int j = 0; j < 12; j++)
            TempEncKey[i][j+4] =  IV[j];
    }

    //* Encrypts each block in TempEncKey
    for (int i = 0; i < 4; i++)
        AES_STD_Enc(TempEncKey[i], MasterKey);
    
    //* Assigns the first 8 bytes of TempEncKey[i] to EncKey (32 bytes)
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            EncKey[i*8+j] = TempEncKey[i][j];
    
    return;
}

static void PolyVal(const uint8_t* H, const uint8_t* Block, size_t Size, uint8_t* Output)
{
    //* Dot Constant (Little Endian)
    //* Dot (X,Y) = X*Y*Dot;
    const uint8_t Dot[16] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x92};

    for (size_t i = 0; i < (Size>>4); i++)
    {
        for (int j = 0; j < 16; j++)
            Output[j] ^= Block[i*16+j];
        SBlockMul(Output, H, Output);
        SBlockMul(Output, Dot, Output);
    }
    
    //* If final Block is incomplete, pad with 0's first
    if (Size % 16 != 0)
    {
        for (size_t j = 0; j < Size%16; j++)
            Output[j] ^= Block[Size-(Size%16)+j];
        for (int j = Size%16; j < 16; j++)
                    Output[j] ^= 0;
        //* Dot (X, Y) = (X * Y * Dot)
        SBlockMul(Output, H, Output);
        SBlockMul(Output, Dot, Output);
    }
    
}

static void SBlockMul(const uint8_t* X, const uint8_t* Y, uint8_t* Result)
{
    //* X and Y are Little-Endian
    //* They are currently read from bit order high to low (left to right) 89ABCDEF 01234567
    //* Change that to be from bit order low to high (right to left)       FEDCBA98 76543210
    uint8_t XCpy[16];
    uint8_t YCpy[16];
    for (int i = 0 ; i < 16; i++)
    {
        XCpy[i] = X[i];
        YCpy[i] = Y[i];
        Result[i] = 0;
    }

    for (int i = 0; i < 128; i++)
    {
        //* BitArr is depedent, double check math on BitArr. Currently pulls Little-Endian, left to right (76543210)
        if (SivBitArr(YCpy, i) == 1)
            for (int i = 0 ; i < 16; i++)
                Result[i] ^= XCpy[i];

        //* BitArr is dependent, Shift is depedent
        if (SivBitArr(XCpy, 127) == 0)
        {            
            // Bigger bits -> Smaller bits
            // x[14] -> x[15]
            // x[15] = (x[14] & 1) ++ (X[15] >> 1) = aaaaaaa(a) ++ (bbbbbbb)b = abbbbbbb

            // FEDCBA98 76543210 -> EDCBA98_ 6543210F
            // Bigger bits -> Smaller bits
            // x[14] -> x[15]
            // x[15] = (x[15] << 1) ++ (x[14] & 0x80) = (bbbbbbb)b + (a)aaaaaaa = bbbbbbba 
            for (int i = 15; i > 0; i--)
                XCpy[i] = ((XCpy[i]) << 1) | (XCpy[i-1] >> 7);
            XCpy[0] = (XCpy[0] << 1);
        }
        else
        {
            for (int i = 15; i > 0; i--)
                XCpy[i] = ((XCpy[i]) << 1) | (XCpy[i-1] >> 7);
            XCpy[0] = (XCpy[0] << 1);
            
            //* V ^= R
            //! Endian-ness accounted for, and bit order.
            XCpy[15] ^= 0b11000010;
            XCpy[0]  ^= 0b00000001;
        }
    }
    return;
}

static void SivCTR(uint8_t* Plaintext, size_t Size, const uint8_t* Key, const uint8_t* IV)
{
    //* Setup CtrBlock and StreamBlock
    uint8_t CtrBlock[16] = {IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7], IV[8], IV[9], IV[10], IV[11], IV[12], IV[13], IV[14], IV[15]};
    uint8_t StreamBlock[16];

    for (int i = 0; i < Size/16; i++)
    {
        //* Gen StreamBlock
        for (int j = 0; j < 16; j++)
            StreamBlock[j] = CtrBlock[j];
        AES_STD_Enc(StreamBlock, Key);

        //* Increment CtrBlock (First 4 bytes as uint32_t LE)
        ((uint32_t*) CtrBlock)[0]++;

        //* Encrypt Plaintext
        for (int j = 0; j < 16; j++)
            Plaintext[j] ^= StreamBlock[j];
    }
    //* Gen StreamBlock
    for (int j = 0; j < 16; j++)
        StreamBlock[j] = CtrBlock[j];
    AES_STD_Enc(StreamBlock, Key);

    //* Encrypt Plaintext (Incomplete block)
    for (size_t j = 0; j < Size%16; j++)
        Plaintext[Size-(Size%16)+j] ^= StreamBlock[j];

    return;
}

static uint8_t SBoxFunc(uint8_t Byte)
{
    uint8_t Inv = GInv(Byte);
    return Inv ^ ROTL8(Inv, 1) ^ ROTL8(Inv, 2) ^ ROTL8(Inv, 3) ^ ROTL8(Inv, 4) ^ 0x63;
}

static uint8_t InvSBoxFunc(uint8_t Byte)
{
    Byte = ROTL8(Byte, 1) ^ ROTL8(Byte, 3) ^ ROTL8(Byte, 6) ^ 0x05;
    return GInv(Byte);
}

void InitSBox()
{
    for (int i = 0; i < 256; i++)
        SBox[i] = SBoxFunc(i);
    return;
}

void InitInvSBox()
{
    for (int i = 0; i < 256; i++)
        InvSBox[i] = InvSBoxFunc(i);
    return;
}
