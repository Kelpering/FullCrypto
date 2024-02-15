# AES-256

A project written entirely in C, designed to be an implementation of AES-256, not cryptographically secure.

## Methods

### AESEnc()

Encrypts a block of 16 bytes of plaintext into 16 bytes of ciphertext, using a symmetric key.

```C
int main()
{
    // Data is exactly 16 bytes of plaintext to encrypt.
    uint8_t Data[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    // Key is exactly 32 bytes, used as a symmetric key for both encryption and decryption.
    uint8_t Key[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

    // Overwrites Data with ciphertext.
    AESEnc(Data, Key);

    // Data[0] == 0x8E

    return 0;
}
```

### AESDec()

Decrypts a block of 16 bytes of ciphertext into 16 bytes of plaintext, using a symmetric key.

```C
int main()
{
    // Data is exactly 16 bytes of ciphertext to decrypt.
    uint8_t Data[16] = {0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF, 0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89};
    // Key is exactly 32 bytes, used as a symmetric key for both encryption and decryption.
    uint8_t Key[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

    // Overwrites Data with plaintext.
    AESDec(Data, Key);

    // Data[0] == 0x00

    return 0;
}
```

### AESKeyGen256()

Insecurely generates a random key of 32-byte length. Used for testing only.

```C
int main()
{
    // Data is exactly 16 bytes of plaintext to encrypt.
    uint8_t Data[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    // Key is generated and must be freed at the end of usage. This function is highly insecure, only use for testing.
    uint8_t* Key = AESKeyGen256(time(NULL));

    AESEnc(Data, Key);

    // Data[0] == Unknown.

    AESDec(Data, Key)

    // Data[0] == 0x00

    // Key must be freed at the end of use.
    free(Key);
    return 0;
}
```
