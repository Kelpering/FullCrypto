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
    uint8_t Plaintext[] = "This is some test data.";
    uint8_t AAD[] = "AAD TEST DATA";
    uint8_t *Key = AES_KeyGen256(time(NULL));
    uint8_t *IV = AES_IVGen(time(NULL), 12);

    // uint8_t* Tag = AES_GCM_Enc(Plaintext, sizeof(Plaintext), AAD, sizeof(AAD), Key, IV);
    // PrintInfo(Plaintext, sizeof(Plaintext), false); 
    // PrintInfo(AAD, sizeof(AAD), true);
    // PrintInfo(Tag, 16, false);
    
    // bool IsValid = AES_GCM_Dec(Plaintext, sizeof(Plaintext), AAD, sizeof(AAD), Tag, Key, IV);
    // printf("\nIsValid: %s", (IsValid) ? "true" : "false");
    // PrintInfo(Plaintext, sizeof(Plaintext), IsValid); 
    
    // free(Tag);  //! Must de-allocate Tag
    AES_GCM_SIV_Enc(Plaintext, sizeof(Plaintext), AAD, sizeof(AAD), Key, IV);

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
            printf("0x%.2X ", Array[i]);
    }
    printf("\n");
    return;
}