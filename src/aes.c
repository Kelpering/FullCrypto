#include "../include/aes.h"
#include "../include/aes_private.h"

//* Public functions
//? AES standard implementation

ErrorCode aes_std_enc(uint8_t* Plaintext, const uint8_t* Key)
{
    //? If SBox has never been run before, initialize.
    if (SBox[0] != 0x63)
        init_sbox();

    //? Fill state sideways
    uint8_t State[16] = 
    {
        Plaintext[0], Plaintext[4], Plaintext[8], Plaintext[12],
        Plaintext[1], Plaintext[5], Plaintext[9], Plaintext[13],  
        Plaintext[2], Plaintext[6], Plaintext[10], Plaintext[14],  
        Plaintext[3], Plaintext[7], Plaintext[11], Plaintext[15]
    };

    //? Key expansion
    uint8_t* EKey = expand_key_256(Key);
    if (EKey == NULL)
        return malloc_error;

    //? Xor first Key
    add_round_key(State, (EKey + 0*4));

    //? Rounds
    for (int i = 1; i < 14; i++)
    {
        sub_bytes(State);
        shift_rows(State);
        mix_columns(State);
        add_round_key(State, (EKey+(i*16)));
    }

    //? Final round without Mix Columns
    sub_bytes(State);
    shift_rows(State);
    add_round_key(State, (EKey+(14*16)));

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

    return success;
}

ErrorCode aes_std_dec(uint8_t* Ciphertext, const uint8_t* Key)
{
    //? If InvSBox has never been run before, initialize.
    if (InvSBox[0] != 0x63)
        init_inv_sbox();
    

    //? Fill state sideways
    uint8_t State[] = 
    {
        Ciphertext[0], Ciphertext[4], Ciphertext[8], Ciphertext[12],
        Ciphertext[1], Ciphertext[5], Ciphertext[9], Ciphertext[13],
        Ciphertext[2], Ciphertext[6], Ciphertext[10], Ciphertext[14],
        Ciphertext[3], Ciphertext[7], Ciphertext[11], Ciphertext[15]
    };

    //? Key expansion
    uint8_t* EKey = expand_key_256(Key);
    if (EKey == NULL)
        return malloc_error;

    //? Xor last key
    add_round_key(State, (EKey + 14*16));

    //? Rounds in reverse
    for (int i = 14; i > 1; i--)
    {
        inv_shift_rows(State);
        inv_sub_bytes(State);
        add_round_key(State, EKey+((i - 1)*16));
        inv_mix_columns(State);
    }

    //? Last round without mix columns
    inv_shift_rows(State);
    inv_sub_bytes(State);
    add_round_key(State, EKey + 0);
    
    //? Clear and de-allocate Expanded Key
    for (int i = 0; i < 240; i++)
        EKey[i] = 0;
    free(EKey);

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

    return success;
}


//? AES-ECB implementation

ErrorCode aes_ecb_enc(const uint8_t* Plaintext, size_t Size, const uint8_t* Key, ByteArr* Ret)
{
    if (Size == 0)
        return unknown_error;

    //? Declare variables & ByteArr struct
    uint8_t PadByte = 16 - (Size%16);
    Ret->Size = Size + PadByte;
    Ret->Arr = malloc(Ret->Size);
    if (Ret->Arr == NULL)
        return malloc_error;

    //? Copy over Plaintext to NewArr, then Pad to a multiple of 16
    for (size_t i = 0; i < Size; i++)
        Ret->Arr[i] = Plaintext[i];
    for (size_t i = Size; i < Ret->Size; i++)
        Ret->Arr[i] = PadByte;

    //? Encrypt each 16 byte block.
    for (size_t i = 0; i < Ret->Size; i+=16)
    {
        ErrorCode TempError = aes_std_enc(Ret->Arr + i, Key);
        if (TempError != success)
        {
            free(Ret->Arr);
            return TempError;
        }
    }

    return success;
}

ErrorCode aes_ecb_dec(const uint8_t* Ciphertext, size_t Size, const uint8_t* Key, ByteArr* Ret)
{
    if (Size == 0 || Size%16 != 0)
        return unknown_error;

    //? Copy over Ciphertext
    uint8_t* Temp = malloc(Size);
    if (Temp == NULL)
        return malloc_error;
    for (size_t i = 0; i < Size; i++)
        Temp[i] = Ciphertext[i];

    //? Decrypt Temp, 16 bytes at a time
    for (size_t i = 0; i < Size; i+=16)
    {
        ErrorCode TempError = aes_std_dec(Temp + i, Key);
        if (TempError != success)
        {
            free(Temp);
            return TempError;
        }
    }

    //? Declare ByteArr Struct
    Ret->Size = Size - Temp[Size-1];
    Ret->Arr = malloc(Ret->Size);
    if (Ret->Arr == NULL)
    {
        free(Temp);
        return malloc_error;
    }

    //? Copy over Temp to ByteArr
    for (size_t i = 0; i < Size-Temp[Size-1]; i++)
        Ret->Arr[i] = Temp[i];

    //? Free allocated Temp
    free (Temp);

    return success;
}


//? AES-CBC implementation

ErrorCode aes_cbc_enc(const uint8_t* Plaintext, size_t Size, const uint8_t* Key, const uint8_t* IV, ByteArr* Ret)
{
    if (Size == 0)
        return unknown_error;

    uint8_t PadByte = 16 - (Size%16);
    Ret->Size = PadByte + Size;
    Ret->Arr = malloc(Ret->Size);
    if (Ret->Arr == NULL)
        return malloc_error;

    //? Fill NewArr with relevant data and padding.
    for (size_t i = 0; i < Size; i++)
        Ret->Arr[i] = Plaintext[i];
    for (size_t i = Size; i < Ret->Size; i++)
        Ret->Arr[i] = PadByte;

    for (int i = 0; i < 16; i++)
        Ret->Arr[i] ^= IV[i];
    for (size_t i = 0; i < Ret->Size - 16; i+=16)
    {
        ErrorCode TempError = aes_std_enc(Ret->Arr+i, Key);
        if (TempError != success)
        {
            free(Ret->Arr);
            return TempError;
        }
        for (int j = 0; j < 16; j++)
            Ret->Arr[i+16 + j] ^= Ret->Arr[i + j];
    }
    // Final one without CBC function
    ErrorCode TempError = aes_std_enc(Ret->Arr+Ret->Size-16, Key);
    if (TempError != success)
    {
        free(Ret->Arr);
        return TempError;
    }
    
    return success;
}

ErrorCode aes_cbc_dec(const uint8_t* Ciphertext, size_t Size, const uint8_t* Key, const uint8_t* IV, ByteArr* Ret)
{
    if (Size == 0 || Size%16 != 0)
        return unknown_error;

    //? Copy over Ciphertext
    uint8_t* Temp = malloc(Size);
    if (Temp == NULL)
        return malloc_error;
    for (size_t i = 0; i < Size; i++)
        Temp[i] = Ciphertext[i];

    //? Decrypt Temp, 16 bytes at a time
    for (size_t i = 0; i < Size; i+=16)
    {
        ErrorCode TempError = aes_std_dec(Temp + i, Key);
        if (TempError != success)
        {
            free(Temp);
            return TempError;
        }
    }

    //? XOR each Ciphertext
    for (int i = 0; i < 16; i++)
        Temp[i] ^= IV[i];
    for (size_t i = 16; i < Size; i++)
        Temp[i] ^= Ciphertext[i-16];

    //? Declare ByteArr Struct
    Ret->Size = Size - Temp[Size - 1];
    Ret->Arr = malloc(Ret->Size);
    if (Ret->Arr == NULL)
    {
        free(Temp);   
        return malloc_error;
    }

    //? Copy over Temp to ByteArr
    for (size_t i = 0; i < Ret->Size; i++)
        Ret->Arr[i] = Temp[i];
        
    //? Free allocated Temp
    free(Temp);
    
    return success;
}


//? AES-GCM implementation

ErrorCode aes_gcm_enc(uint8_t* Plaintext, size_t PSize, const uint8_t* AAD, size_t ASize, const uint8_t* Key, const uint8_t* IV, uint8_t* Tag)
{
    //* Zero block (encrypted)
    uint8_t H[16] = {0};
    ErrorCode TempError;
    TempError = aes_std_enc(H, Key);
    if (TempError != success)
        return TempError;

    //* J (IV) and JInc (ginc32(J))
    uint8_t J[16] =    {IV[0],IV[1],IV[2],IV[3],IV[4],IV[5],IV[6],IV[7],IV[8],IV[9],IV[10],IV[11],0,0,0,1};
    uint8_t JInc[16] = {IV[0],IV[1],IV[2],IV[3],IV[4],IV[5],IV[6],IV[7],IV[8],IV[9],IV[10],IV[11],0,0,0,2};

    //* Encrypt Plaintext here via gctr. (Ciphertext)
    TempError = gctr(Plaintext, PSize, Key, JInc);
    if (TempError != success)
        return TempError;

    //* Initial hash block must be 0.
    uint8_t* Hash = calloc(16, 1);
    if (Hash == NULL)
        return malloc_error;
    uint8_t LenBuf[16];
    //^ TempSizes are endian dependent. Convert (even if already) little endian
    size_t TempASize = ASize<<3;
    size_t TempPSize = PSize<<3;
    for(int i = 0; i < 8; i++)
    {
        // LenBuf[i] = ((uint8_t*) &TempASize)[7-i];
        // LenBuf[i+8] = ((uint8_t*) &TempPSize)[7-i];

        //^ Take Largest to Smallest TempSize
        //! Untested
        LenBuf[i] = (TempASize >> (7-i)*(8)) & 0xFF;
        LenBuf[i + 8] = (TempPSize >> (7-i)*(8)) & 0xFF;
    }

    //* Hash = ghash(AAD+0 Pad + PSize + 0 Pad + ASize[bits] + PSize[bits])
    //* Using ghash's last block as a first block works the same as concatenating the entire bit string.
    ghash(H, AAD, ASize, Hash);
    ghash(H, Plaintext, PSize, Hash);
    ghash(H, LenBuf, 16, Hash);

    //* Encrypt Hash with Key (Tag)
    TempError = gctr(Hash, 16, Key, J);
    if (TempError != success)
    {
        free(Hash);
        return TempError;
    }

    //* Assume tag is allocated
    for (int i = 0; i < 16; i++)
        Tag[i] = Hash[i];

    return success;
}

ErrorCode aes_gcm_dec(uint8_t* Ciphertext, size_t CSize, const uint8_t* AAD, size_t ASize, const uint8_t* Key, const uint8_t* IV, const uint8_t* Tag)
{
    //* Zero block (encrypted)
    uint8_t H[16] = {0};
    ErrorCode TempError;
    TempError = aes_std_enc(H, Key);
    if (TempError != success)
        return TempError;

    //* J (IV) and JInc (ginc32(J))
    uint8_t J[16] =    {IV[0],IV[1],IV[2],IV[3],IV[4],IV[5],IV[6],IV[7],IV[8],IV[9],IV[10],IV[11],0,0,0,1};
    uint8_t JInc[16] = {IV[0],IV[1],IV[2],IV[3],IV[4],IV[5],IV[6],IV[7],IV[8],IV[9],IV[10],IV[11],0,0,0,2};

    //* Initial hash block must be 0.
    uint8_t Hash[16] = {0};     // Changed from calloc(16,1);

    uint8_t LenBuf[16];
    size_t TempASize = ASize<<3;
    size_t TempCSize = CSize<<3;
    for(int i = 0; i < 8; i++)
    {
        // LenBuf[i] = ((uint8_t*) &TempASize)[7-i];
        // LenBuf[i+8] = ((uint8_t*) &TempCSize)[7-i];

        //! Untested
        LenBuf[i] = (TempASize >> (7-i)*(8)) & 0xFF;
        LenBuf[i + 8] = (TempCSize >> (7-i)*(8)) & 0xFF;
    }

    //* Hash = ghash(AAD+0 Pad + PSize + 0 Pad + ASize[bits] + PSize[bits])
    //* Using ghash's last block as a first block works the same as concatenating the entire bit string.
    ghash(H, AAD, ASize, Hash);
    ghash(H, Ciphertext, CSize, Hash);
    ghash(H, LenBuf, 16, Hash);

    //* Encrypt Hash with Key (Tag)
    TempError = gctr(Hash, 16, Key, J);
    if (TempError != success)
        return TempError;

    //* Validates (Ciphertext + AAD + Tag)
    bool IsValid = true;
    for (int i = 0; i < 16; i++)
        if (Tag[i] != Hash[i])
            IsValid = false;
    
    //* If invalid, return without modifying Ciphertext.
    if (IsValid == false)
        return unknown_error;
    
    //* Decipher Ciphertext and return.
    return gctr(Ciphertext, CSize, Key, JInc);
}


//? AES-GCM-SIV Implementation

ErrorCode aes_siv_enc(uint8_t* Plaintext, size_t PSize, const uint8_t* AAD, size_t ASize, const uint8_t* Key, const uint8_t* IV, uint8_t* Tag)
{
    //* Allocate and initialize EncKey and AuthKey
    uint8_t EncKey[32];
    uint8_t AuthKey[16];
    ErrorCode TempError;
    TempError = siv_derive_keys(Key, IV, EncKey, AuthKey);
    if (TempError != success)
        return TempError;

    //* Assume RetTag is already allocated (Dynamic or Static) (initialized to 0).
    for (int i = 0; i < 16; i++)
        Tag[i] = 0;

    //* Calculate Length Block for polyval later. (Bit size)
    uint64_t LenBlock[2] = {(ASize<<3), (PSize<<3)};
    
    //* Run polyval for AAD, Plaintext, LenBlock in sequence.
    polyval(AuthKey, AAD, ASize, Tag);
    polyval(AuthKey, Plaintext, PSize, Tag);
    polyval(AuthKey, ((uint8_t*) LenBlock), 16, Tag);

    //* Xor first 12 bytes of Tag with IV
    for (int i = 0; i < 12; i++)
        Tag[i] ^= IV[i];

    //* Clear MSB of last byte in Tag
    Tag[15]  &= 0x7F;

    //* Produce final Tag version
    TempError = aes_std_enc(Tag, EncKey);
    if (TempError != success)
    {
        free(Tag);
        return TempError;
    }

    //* Generates ICB for SivCtr
    uint8_t ICB[16] = {Tag[0], Tag[1], Tag[2], Tag[3], Tag[4], Tag[5], Tag[6], Tag[7], Tag[8], Tag[9], Tag[10], Tag[11], Tag[12], Tag[13], Tag[14], (Tag[15] | 0x80)};

    //* Encrypt Plaintext with SivCtr (Ciphertext)
    TempError = sivctr(Plaintext, PSize, EncKey, ICB);
    if (TempError != success)
    {
        free(Tag);
        return TempError;
    }

    return success;
}

ErrorCode aes_siv_dec(uint8_t* Ciphertext, size_t CSize, const uint8_t* AAD, size_t ASize, const uint8_t* Key, const uint8_t* IV, const uint8_t* Tag)
{
    //* Allocate and initialize EncKey and AuthKey
    uint8_t EncKey[32];
    uint8_t AuthKey[16];
    ErrorCode TempError;
    TempError = siv_derive_keys(Key, IV, EncKey, AuthKey);
    if (TempError != success)
        return TempError;

    //* Generates ICB for SivCtr
    uint8_t ICB[16] = {Tag[0], Tag[1], Tag[2], Tag[3], Tag[4], Tag[5], Tag[6], Tag[7], Tag[8], Tag[9], Tag[10], Tag[11], Tag[12], Tag[13], Tag[14], (Tag[15] | 0x80)};

    //* Malloc a Plaintext for indirect encryption, to prevent unauthenticated output.
    uint8_t* Plaintext = malloc(CSize);
    if (Plaintext == NULL)
        return malloc_error;
    for(int i = 0; i < CSize; i++)
        Plaintext[i] = Ciphertext[i];

    //* Decrypt Plaintext with SivCtr
    TempError = sivctr(Plaintext, CSize, EncKey, ICB);
    if (TempError != success)
    {
        free(Plaintext);
        return TempError;
    }

    //* mallloc Tag (initialized to 0).
    //// uint8_t* PolyHash = calloc(16, 1);
    uint8_t PolyHash[16] = {0}; //! Untested

    //* Calculate Length Block for polyval later.
    uint64_t LenBlock[2] = {(ASize<<3), (CSize<<3)};
    
    //* Run polyval for AAD, Plaintext, LenBlock in sequence.
    polyval(AuthKey, AAD, ASize, PolyHash);
    polyval(AuthKey, Plaintext, CSize, PolyHash);
    polyval(AuthKey, ((uint8_t*) LenBlock), 16, PolyHash);

    //* Xor first 12 bytes of Tag with IV
    for (int i = 0; i < 12; i++)
        PolyHash[i] ^= IV[i];

    //* Clear MSB of last byte in Tag, then encrypt.
    PolyHash[15]  &= 0x7F;
    TempError = aes_std_enc(PolyHash, EncKey);
    if (TempError != success)
    {
        free(Plaintext);
        return TempError;
    }

    //* Validate Tag in constant time.
    bool IsInvalid = false;
    for (int i = 0; i < 16; i++)
        IsInvalid |= !(Tag[i] == PolyHash[i]);

    //* Handle decryption if Tag happens to be invalid, never overwriting plaintext unless the check was successful.
    if (!IsInvalid)
    {
        for (int i = 0; i < CSize; i++)
            Ciphertext[i] = Plaintext[i];    
        free(Plaintext);
        return success;
    }
    
    free(Plaintext);
    return unknown_error;
}


//? AES non-standard test functions

uint8_t* aes_generate_iv(uint32_t Seed, size_t Size)
{
    srand(Seed);
    uint8_t* IV = malloc(Size);

    for (int i = 0; i < Size; i++)
        IV[i] = rand() % 256;
    return IV;
}


//* Static functions
//? Key Functions

static void add_round_key(uint8_t* State, const uint8_t* EKey)
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            State[j*4+i] ^= EKey[i*4+j];
    return;
}

static uint8_t* expand_key_256(const uint8_t* Key)
{
    //? Malloc a 256-bit expanded key (constant size).
    uint32_t* EKey = malloc(240);
    if (EKey == NULL)
        return NULL;

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
            rot_word((uint8_t*) &Prev);
            sub_word((uint8_t*) &Prev);
            //* RCON is XOR'd directly because of Prev's endianness
            Prev ^= RCON;
            RCON = gmul(RCON, 0x02);
        }
        else if ((i+4)%8 == 0)
        {
            sub_word((uint8_t*) &Prev);
        }

        EKey[i] = EKey[i-8] ^ Prev;
    }

    //! Expanded key must be freed at the end of the AES run.
    return (uint8_t*) EKey;
}

static void rot_word(uint8_t* Word)
{
    uint8_t Temp = Word[0];
    Word[0] = Word[1];
    Word[1] = Word[2];
    Word[2] = Word[3];
    Word[3] = Temp;
    return;
}

static void sub_word(uint8_t* Word)
{
    Word[0] = SBox[Word[0]];
    Word[1] = SBox[Word[1]];
    Word[2] = SBox[Word[2]];
    Word[3] = SBox[Word[3]];
    return;
}


//? Encryption functions

static void shift_rows(uint8_t* State)
{
    uint8_t Temp[16];
    for (int i = 0; i < 16; i++)
        Temp[i] = State[i];

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            State[i*4+j] = Temp[i*4+(j+i)%4];
    return;
}

static void sub_bytes(uint8_t* State)
{
    for (int i = 0; i < 16; i++)
        State[i] = SBox[State[i]];
    return;
}

static void mix_columns(uint8_t* State)
{
    // Stores State while the column is being altered.
    uint8_t Temp[4];

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
            Temp[j] = State[j*4+i];

        State[0*4+i] = gmul(Temp[0], 0x02) ^ gmul(Temp[1], 0x03) ^ Temp[2] ^ Temp[3];
        State[1*4+i] = Temp[0] ^ gmul(Temp[1], 0x02) ^ gmul(Temp[2], 0x03) ^ Temp[3];
        State[2*4+i] = Temp[0] ^ Temp[1] ^ gmul(Temp[2], 0x02) ^ gmul(Temp[3], 0x03);
        State[3*4+i] = gmul(Temp[0], 0x03) ^ Temp[1] ^ Temp[2] ^ gmul(Temp[3], 0x02);
    }
    return;
}


//? Decryption functions

static void inv_shift_rows(uint8_t* State)
{
    uint8_t Temp[16];
    for (int i = 0; i < 16; i++)
        Temp[i] = State[i];

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            State[i*4+(j+i)%4] = Temp[i*4+j];
    return;
}

static void inv_sub_bytes(uint8_t* State)
{
    for (int i = 0; i < 16; i++)
        State[i] = InvSBox[State[i]];
    return;
}

static void inv_mix_columns(uint8_t* State)
{
    // Stores State while the column is being altered.
    uint8_t Temp[4];

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
            Temp[j] = State[j*4+i];

        State[0*4+i] = gmul(Temp[0], 0x0e) ^ gmul(Temp[1], 0x0b) ^ gmul(Temp[2], 0x0d) ^ gmul(Temp[3], 0x09);
        State[1*4+i] = gmul(Temp[0], 0x09) ^ gmul(Temp[1], 0x0e) ^ gmul(Temp[2], 0x0b) ^ gmul(Temp[3], 0x0d);
        State[2*4+i] = gmul(Temp[0], 0x0d) ^ gmul(Temp[1], 0x09) ^ gmul(Temp[2], 0x0e) ^ gmul(Temp[3], 0x0b);
        State[3*4+i] = gmul(Temp[0], 0x0b) ^ gmul(Temp[1], 0x0d) ^ gmul(Temp[2], 0x09) ^ gmul(Temp[3], 0x0e);
    }
    return;
}


//? Universal functions

static uint8_t gmul(uint8_t x, uint8_t y)
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

static uint8_t ginv(uint8_t Byte)
{
    //* Uses combinations of variables to multiply a by itself exactly 254 times.
    uint8_t b = gmul(Byte,Byte);
    uint8_t c = gmul(Byte,b);
            b = gmul(c,c);
            b = gmul(b,b);
            c = gmul(b,c);
            b = gmul(b,b);
            b = gmul(b,b);
            b = gmul(b,c);
            b = gmul(b,b);
            b = gmul(Byte,b);
    return gmul(b,b);
}

static void ginc32(uint8_t* Block)
{
    //^ endian depdenent? 
    //* Reverses the endian of Block (as a 128-bit number) to allow for proper increment.
    uint32_t Temp = (Block[12] << 24) | (Block[13] << 16) | (Block[14] << 8) | Block[15];
    Temp++;
    Block[12] = (Temp >> 24) & 0xFF;
    Block[13] = (Temp >> 16) & 0xFF;
    Block[14] = (Temp >> 8) & 0xFF;
    Block[15] = Temp & 0xFF;
    return;
}

static void gblockmul(const uint8_t* X, const uint8_t* Y, uint8_t* Result)
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
        if (BITARR128(YCpy, i) == 1)
            for (int i = 0 ; i < 16; i++)
                Result[i] ^= XCpy[i];

        if (BITARR128(XCpy, 127) == 0)
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

static void ghash(const uint8_t* H, const uint8_t* Block, size_t Size, uint8_t* Output)
{   
    for (size_t i = 0; i < (Size>>4); i++)
    {
        for (int j = 0; j < 16; j++)
            Output[j] ^= Block[i*16+j];
        gblockmul(Output, H, Output);
    }
    
    //* If final Block is incomplete, pad with 0's first
    if (Size % 16 != 0)
    {
        for (size_t j = 0; j < Size%16; j++)
            Output[j] ^= Block[Size-(Size%16)+j];
        for (int j = Size%16; j < 16; j++)
            Output[j] ^= 0;
        gblockmul(Output, H, Output);
    }
    
    return;
}

static ErrorCode gctr(uint8_t* Plaintext, size_t Size, const uint8_t* Key, const uint8_t* ICB)
{
    //* Prevent Size overflow on last block.
    if (Size == 0)
        return success;

    uint8_t Temp[16];
    uint8_t CB[16];
    for (int i = 0; i < 16; i++)
        CB[i] = ICB[i];

    //* Generate counter, Encrypt Counter, XOR plaintext block with counter.
    for (size_t i = 0; i < Size-(Size%16); i+=16)
    {
        for (size_t j = 0; j < 16; j++)
            Temp[j] = CB[j];
        if (aes_std_enc(Temp, Key) != success)
            return unknown_error;
        for (int j = 0; j < 16; j++)
            Plaintext[i+j] ^= Temp[j];
        ginc32(CB);
    } 
    //* Final Block (works on incomplete blocks)
    for (int j = 0; j < 16; j++)
        Temp[j] = CB[j];
    if (aes_std_enc(Temp, Key) != success)
        return unknown_error;
    for (size_t j = 0; j < Size%16; j++)
        Plaintext[Size-(Size%16)+j] ^= Temp[j];

    return success;
}

static ErrorCode siv_derive_keys(const uint8_t* MasterKey, const uint8_t* IV, uint8_t* EncKey, uint8_t* AuthKey)
{
    //? AuthKey
    //* Generates TempAuthKey for AuthKey (16 bytes)
    uint8_t TempAuthKey[2][16];
    for (int i = 0; i < 2; i++)
    {
        //^ Endian Dependent
        //! Neither endian's in this func are tested
        //* Should be little endian
        // ((uint32_t*) TempAuthKey[i])[0] = i;
        TempAuthKey[i][0] = i;
        TempAuthKey[i][1] = 0;
        TempAuthKey[i][2] = 0;
        TempAuthKey[i][3] = 0;


        //* Rest is IV
        for (int j = 0; j < 12; j++)
            TempAuthKey[i][j+4] =  IV[j];
    }

    //* Encrypts each block in TempAuthKey
    for (int i = 0; i < 2; i++)
    {
        ErrorCode TempError = aes_std_enc(TempAuthKey[i], MasterKey);
        if (TempError != success)
            return TempError;
    }

    //* Assigns the first 8 bytes of TempAuthKey[i] to AuthKey (16 bytes)
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < 8; j++)
            AuthKey[i*8+j] = TempAuthKey[i][j];


    //? EncKey
    //* Generates TempEncKey for EncKey (32 bytes)
    uint8_t TempEncKey[4][16];
    for (int i = 0; i < 4; i++)
    {
        //^ Endian Dependent
        //* Should be little endian
        // ((uint32_t*) TempEncKey[i])[0] = i+2;
        TempEncKey[i][0] = i+2;
        TempEncKey[i][1] = 0;
        TempEncKey[i][2] = 0;
        TempEncKey[i][3] = 0;


        //* Rest is IV
        for (int j = 0; j < 12; j++)
            TempEncKey[i][j+4] =  IV[j];
    }

    //* Encrypts each block in TempEncKey
    for (int i = 0; i < 4; i++)
    {
        ErrorCode TempError = aes_std_enc(TempEncKey[i], MasterKey);
        if (TempError != success)
            return TempError;
    }
    
    //* Assigns the first 8 bytes of TempEncKey[i] to EncKey (32 bytes)
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            EncKey[i*8+j] = TempEncKey[i][j];
    
    return success;
}

static void polyval(const uint8_t* H, const uint8_t* Block, size_t Size, uint8_t* Output)
{
    //* Dot Constant (Little Endian)
    //* Dot (X,Y) = X*Y*Dot;
    const uint8_t Dot[16] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x92};

    for (size_t i = 0; i < (Size>>4); i++)
    {
        for (int j = 0; j < 16; j++)
            Output[j] ^= Block[i*16+j];
        sblockmul(Output, H, Output);
        sblockmul(Output, Dot, Output);
    }
    
    //* If final Block is incomplete, pad with 0's first
    if (Size % 16 != 0)
    {
        for (size_t j = 0; j < Size%16; j++)
            Output[j] ^= Block[Size-(Size%16)+j];
        for (int j = Size%16; j < 16; j++)
                    Output[j] ^= 0;
        //* Dot (X, Y) = (X * Y * Dot)
        sblockmul(Output, H, Output);
        sblockmul(Output, Dot, Output);
    }
    
}

static void sblockmul(const uint8_t* X, const uint8_t* Y, uint8_t* Result)
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
        if (SIVBITARR(YCpy, i) == 1)
            for (int i = 0 ; i < 16; i++)
                Result[i] ^= XCpy[i];

        //* BitArr is dependent, Shift is depedent
        if (SIVBITARR(XCpy, 127) == 0)
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

static ErrorCode sivctr(uint8_t* Plaintext, size_t Size, const uint8_t* Key, const uint8_t* IV)
{
    //* Setup CtrBlock and StreamBlock
    uint8_t CtrBlock[16] = {IV[0], IV[1], IV[2], IV[3], IV[4], IV[5], IV[6], IV[7], IV[8], IV[9], IV[10], IV[11], IV[12], IV[13], IV[14], IV[15]};
    uint8_t StreamBlock[16];

    for (int i = 0; i < Size/16; i++)
    {
        //* Gen StreamBlock
        for (int j = 0; j < 16; j++)
            StreamBlock[j] = CtrBlock[j];
        ErrorCode TempError = aes_std_enc(StreamBlock, Key);
        if (TempError != success)
            return TempError;

        //* Increment CtrBlock (First 4 bytes as uint32_t LE)
        ((uint32_t*) CtrBlock)[0]++;

        //* Encrypt Plaintext
        for (int j = 0; j < 16; j++)
            Plaintext[i*16+j] ^= StreamBlock[j];
    }
    //* Gen StreamBlock
    for (int j = 0; j < 16; j++)
        StreamBlock[j] = CtrBlock[j];
    ErrorCode TempError = aes_std_enc(StreamBlock, Key);
    if (TempError != success)
        return TempError;

    //* Encrypt Plaintext (Incomplete block)
    for (size_t j = 0; j < Size%16; j++)
        Plaintext[Size-(Size%16)+j] ^= StreamBlock[j];

    return success;
}

static uint8_t sbox_func(uint8_t Byte)
{
    uint8_t Inv = ginv(Byte);
    return Inv ^ ROTL8(Inv, 1) ^ ROTL8(Inv, 2) ^ ROTL8(Inv, 3) ^ ROTL8(Inv, 4) ^ 0x63;
}

static uint8_t inv_sbox_func(uint8_t Byte)
{
    Byte = ROTL8(Byte, 1) ^ ROTL8(Byte, 3) ^ ROTL8(Byte, 6) ^ 0x05;
    return ginv(Byte);
}

void init_sbox()
{
    for (int i = 0; i < 256; i++)
        SBox[i] = sbox_func(i);
    return;
}

void init_inv_sbox()
{
    for (int i = 0; i < 256; i++)
        InvSBox[i] = inv_sbox_func(i);
    return;
}
