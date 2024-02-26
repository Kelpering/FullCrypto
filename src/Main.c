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

int main()
{   
    uint8_t Plaintext[] = {0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
    uint8_t AAD[] = {0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};
    uint8_t *Key = AES_KeyGen256(time(NULL));
    uint8_t *IV = AES_IVGen(time(NULL), 12);

    uint8_t* Tag = AES_GCM_Enc(Plaintext, sizeof(Plaintext), AAD, sizeof(AAD), Key, IV);
    PrintInfo(Plaintext, sizeof(Plaintext), false); 
    PrintInfo(Tag, 16, false);
    
    bool IsValid = AES_GCM_Dec(Plaintext, sizeof(Plaintext), AAD, sizeof(AAD), Tag, Key, IV);
    printf("\nIsValid: %s", (IsValid) ? "true" : "false");
    PrintInfo(Plaintext, sizeof(Plaintext), false); 
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