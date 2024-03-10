#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include "../include/AES.h"
#include "../include/Base64.h"
#include "../include/MD5.h"

void PrintInfo(uint8_t* Array, size_t Size, bool isString);
void StrToHex(char *Str);

int main()
{   
    //^ TODO
    //* Test AES_GCM_SIV against RFC 8452
    //^ Add error detection / reporting (Malloc, failure to encrypt/decrypt, etc).
    //^ Standardize function I/O
    //^ Fix all Endian aligned data manip to be compatible cross platform.
    //^ Document / Re-document code
    //^ Refactor code to look nice

    //^ Reprogram a majority of AES to be more standard and meet current code expectations.
    //! Multithread support?

    uint8_t Plaintext[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4d, 0xb9, 0x23, 0xdc, 0x79, 0x3e, 0xe6, 0x49, 0x7c, 0x76, 0xdc, 0xc0, 0x3a, 0x98, 0xe1, 0x08};
    uint8_t AAD[] = {0x9c, 0x21, 0x59, 0x05, 0x8b, 0x1f, 0x0f, 0xe9, 0x14, 0x33, 0xa5, 0xbd, 0xc2, 0x0e, 0x21, 0x4e, 0xab, 0x7f, 0xec, 0xef, 0x44, 0x54, 0xa1, 0x0e, 0xf0, 0x65, 0x7d, 0xf2, 0x1a, 0xc7};
    uint8_t Key[32] = {0};
    uint8_t IV[12] = {0};
    
    uint8_t* Tag = AES_GCM_SIV_Enc(Plaintext, sizeof(Plaintext), AAD, sizeof(AAD), Key, IV);
    PrintInfo(Plaintext, sizeof(Plaintext), false);
    PrintInfo(Tag, 16, false);

    bool valid = AES_GCM_SIV_Dec(Plaintext, sizeof(Plaintext), AAD, sizeof(AAD), Tag, Key, IV);
    PrintInfo(Plaintext, sizeof(Plaintext), false);
    printf("IsValid: %s\n", (valid)? "Yes" : "No");

    free(Tag);
    return 0;
}

void PrintInfo(uint8_t* Array, size_t Size, bool isString)
{
    if (isString)
    {
        printf("\nData is string.\nString: \"%s\"", Array);
    }
    else
    {
        printf("\nData is not string.\nSize: %lu\n", Size);
        for (size_t i = 0; i < Size; i++)
            printf("%.2x", Array[i]);
    }
    printf("\n");
    return;
}

//! Awful code used only for testing, probably leaks and destroys memory OoB, use in seperate runs exclusively for converting to hex strings.
void StrToHex(char *Str)
{
    size_t Count = 0;
    while (Str[Count++] != '\0');

    char *HexStr = malloc((Count<<1) + Count - 2);

    for (size_t i = 0, j=0; i < Count-2; i+=2, j+=6)
    {
        HexStr[j+0] = '0';
        HexStr[j+1] = 'x';
        HexStr[j+2] = Str[i];
        HexStr[j+3] = Str[i+1];
        HexStr[j+4] = ',';
        HexStr[j+5] = ' ';
    }
    HexStr[(Count<<1) + Count - 3] = '\0';
    printf("%s\n", HexStr);
    free(HexStr);

    return;
}