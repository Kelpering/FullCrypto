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

//? AES non-standard test functions

uint8_t* AES_KeyGen256(uint32_t Seed)
{
    srand(Seed);
    uint8_t* Key256 = malloc(32);

    for (int i = 0; i < 32; i++)
        Key256[i] = rand() % 256;
    return Key256;
}

uint8_t* AES_IVGen(uint32_t Seed)
{
    srand(Seed);
    uint8_t* IV = malloc(16);

    for (int i = 0; i < 16; i++)
        IV[i] = rand() % 256;
    return IV;
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

ByteArr AES_GCM_Enc(uint8_t* Plaintext, size_t PSize, const uint8_t* AAD, size_t ASize, const uint8_t* Key, const uint8_t* IV)
{
    //? IV = 12 bytes
    //? Ciphertext = ? (might be able to overwrite Plaintext)
    //? Authentication Tag = ?-bits/bytes

    //! Required funcs:
    //* GCTR
    //? GHash (Must be tested in the future)
    //* GInc32
    //* GBlockMul

    //* Zero block (encrypted)
    uint8_t H[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    AES_STD_Enc(H, Key);

    //* J (ICB), with GInc32 applied.
    uint8_t J[16] = {IV[0],IV[1],IV[2],IV[3],IV[4],IV[5],IV[6],IV[7],IV[8],IV[9],IV[10],IV[11],0,0,0,2};

    //* Encrypt Plaintext here via GCTR.
    //! Need to test with 2+ blocks, incomplete blocks, etc.
    GCTR(Plaintext, PSize, Key, J);

    // u = 16 * ceil(PSize/16)-PSize | v = 16 * ceil(ASize/16)-ASize
    // PSize = 16, u = 0; PSize = 17, u=47
    // (16-x%16)%16

    // ASize & PSize are already binary and 64 bits (uint64_t)
    // || is concat here
    // S = GHash_h(A || 0^v || C || 0^u || ASize || PSize)
    // Combine AAD + 0^V + Plaintext + 0^U + ASize + PSize
    // Malloc should allocate the correct amount of bytes to copy over.
    //! Are the final two (Sizes) little or big endian?
    //! Start with big, test, then repeat with little.
    // uint8_t ConcatHash = malloc(ASize + (16-(ASize%16))%16 + PSize + (16-(PSize%16))%16 + 8 + 8);
    uint8_t APad = (16-ASize%16)%16;
    uint8_t PPad = (16-PSize%16)%16;
    uint8_t* ConcatHash = malloc (ASize+PSize+APad+PPad+16);
    size_t CurSize = 0;
    
    for (size_t i = 0; i < ASize; i++)
        ConcatHash[i] = AAD[i];
    CurSize += ASize;

    for (size_t i = 0; i < APad; i++)
        ConcatHash[i+CurSize] = 0;
    CurSize += APad;
    
    // //* Plaintext here has already been encrypted.
    for (size_t i = 0; i < PSize; i++)
        ConcatHash[i+CurSize] = Plaintext[i];
    CurSize += PSize;

    for (size_t i = 0; i < PPad; i++)
        ConcatHash[i+CurSize] = 0;
    CurSize += PPad;

    for (size_t i = 0; i < 8; i++)
        ConcatHash[i+CurSize] = ((uint8_t*) &ASize)[7-i];
    CurSize += 8;

    for (size_t i = 0; i < 8; i++)
        ConcatHash[i+CurSize] = ((uint8_t*) &PSize)[7-i];

    for (int i = 0; i < ASize+PSize+APad+PPad+16; i++)
        printf("0x%.2X ", ConcatHash[i]);

    uint8_t Hash[16];
    printf("\n\n");
    GHash(H, ConcatHash, (ASize+PSize+APad+PPad+16)>>4, Hash);
    GCTR(Hash, 16, Key, J);

    for (int i = 0; i < 16; i++)
        printf("0x%.2X ", Hash[i]);

    return (ByteArr){NULL, 0};
}

ByteArr AES_GCM_Dec(const uint8_t* Plaintext, size_t Size, const uint8_t* Key, const uint8_t* IV)
{
    //! We must return FAIL here if there is an error (aka tampering/mis-match)
    return (ByteArr){NULL, 0};
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

static void GBlockMul(uint8_t* X, uint8_t* Y, uint8_t* Result)
{
    //? Each block is a uint8_t[16] array, which represents a 128-bit number.
    uint8_t XCpy[16];
    uint8_t YCpy[16];
    for (int i = 0 ; i < 16; i++)
    {
        XCpy[i] = X[i];     //* V
        YCpy[i] = Y[i];     //* Y
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

static void GHash(uint8_t* H, uint8_t* Block, size_t BlockNum, uint8_t* Output)
{   
    //! Check here, seems broken.
    //! Somewhere for Tag, between GHash and GCTR is broken, hash hasnt passed tests. 
    //! Also, when using no H, it seems like it spat back the encryption (makes no sense)
    //! So here is where its broken.
    //* Allocates Y and initializes to '0'
    uint8_t* Y = calloc(BlockNum, 16);

    for (int i = 1; i < BlockNum; i++)
    {
        //* Y[i] = Y[i-1] ^ X[i]
        for (int j = 0; j < 16; j++)
            Y[i*16+j] = Y[(i-1)*16+j] ^ Block[i*16+j];

        //* Y[i] = (Y * X) (in GF(2^128))
        GBlockMul(&Y[i*16], H, &Y[i*16]);
    }
    
    // Return and Free Y
    for (int j = 0; j < 16; j ++)
        Output[j] = Y[(BlockNum-1)*16+j];
    free(Y);
    return;
}

static void GCTR(uint8_t* Plaintext, size_t Size, const uint8_t* Key, const uint8_t* ICB)
{
    //? Pre-approved cipher (AES)
    //? Key (256-bit AES key)
    //? Initial Counter Block (modified IV?)
    //? Bit string X (arbitrary length) (now needs size) (make byte)
    //? Output: Y of length len(X) (can overwrite X?)

    // If empty, return 0 (might be automatic, check later).
    if (Size == 0)
        return;

    // Calculate n (Number of blocks (16 bytes or 128-bits))
    size_t BlockNum = Size;
    if (Size%16 != 0)
        BlockNum+=16;
    BlockNum >>= 4;

    //X1 = Plaintext[(1)*16+j]

    // CB1 = ICB
    uint8_t CB[16];
    uint8_t Temp[16];
    for (int i = 0; i < 16; i++)
        CB[i] = ICB[i];

    //for (i = 2 -> n) CB[i] = GInc32(CB[i-1])
    //* Might be able to skip having another array and just reformat CB every time.
   for (int i = 0; i < BlockNum - 1; i++)
   {
       for (int j = 0; j < 16; j++)
            Temp[j] = CB[j];
       AES_STD_Enc(Temp, Key);

       for (int j = 0; j < 16; j++)
            Plaintext[i*16+j] ^= Temp[j];
       GInc32(CB);
       //* CB = Inc32(CB);
       // Plaintext[i] = Plaintext[i] ^ AES(CB[i], Key);
       // CB is 16 bytes, but needs to remain
       // Key is provided
       //! AES_STD_Enc(CB, Key);
       // Put curr CB into variable array, Encrypt that, then plaintext ^= that.
       // Plaintext is unable to be used as it has data in it.
   } 
   //* Final Block
   for (int j = 0; j < 16; j++)
       Temp[j] = CB[j];
   AES_STD_Enc(Temp, Key);
   for (int j = 0; j < Size-(Size%16); j++)
        Plaintext[(BlockNum-1)*16+j] ^= Temp[j];

  
   // Below might be (but isn't always) less than 16 bytes.
   // Plaintext[last]: Xor the last (16 or less) bytes with the same number of bytes AES(CB[last], Key) (Most Significant Bytes)
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
