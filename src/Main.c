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
    uint8_t Plaintext[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4d,0xb9,0x23,0xdc,0x79,0x3e,0xe6,0x49,0x7c,0x76,0xdc,0xc0,0x3a,0x98,0xe1,0x08};
    uint8_t AAD[] = "AAD TEST DATA";
    uint8_t Key[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t IV[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    //! In wrap test, this seems to fail. So fix that.
    uint8_t* Tag = AES_GCM_SIV_Enc(Plaintext, sizeof(Plaintext), NULL, 0, Key, IV);
    PrintInfo(Plaintext, sizeof(Plaintext), false);
    PrintInfo(Tag, 16, false);
    
    bool valid = AES_GCM_SIV_Dec(Plaintext, sizeof(Plaintext), NULL, 0, Tag, Key, IV);
    PrintInfo(Plaintext, sizeof(Plaintext), false);
    printf("BOOL: %d\n", valid);

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
