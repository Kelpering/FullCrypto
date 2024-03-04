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
    uint8_t Plaintext[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t AAD[] = "AAD TEST DATA";
    uint8_t Key[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t IV[] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // uint8_t* Tag = AES_GCM_Enc(Plaintext, sizeof(Plaintext), AAD, sizeof(AAD), Key, IV);
    // PrintInfo(Plaintext, sizeof(Plaintext), false); 
    // PrintInfo(AAD, sizeof(AAD), true);
    // PrintInfo(Tag, 16, false);
    
    // bool IsValid = AES_GCM_Dec(Plaintext, sizeof(Plaintext), AAD, sizeof(AAD), Tag, Key, IV);
    // printf("\nIsValid: %s", (IsValid) ? "true" : "false");
    // PrintInfo(Plaintext, sizeof(Plaintext), IsValid); 
    
    // free(Tag);  //! Must de-allocate Tag
    AES_GCM_SIV_Enc(Plaintext, sizeof(Plaintext), AAD, sizeof(AAD), Key, IV);
    //Tag: 843122130f7364b761e0b97427e3df28
    //Result: c2ef328e5c71c83b843122130f7364b761e0b97427e3df28
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