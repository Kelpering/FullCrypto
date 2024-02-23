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
    uint8_t Plaintext[16] = {1,23,34,51,236,55,34,4,4,4,4,2,32,12,31,12};
    uint8_t* Key = AES_KeyGen256(time(NULL));
    uint8_t IV[12] = {1,2,3,4,5,6,7,8,9,10,11,12};

    AES_GCM_Enc(Plaintext, sizeof(Plaintext), NULL, 0, Key, IV);
    // uint8_t Data[] = "HELLO WORLD!";
    // uint8_t* IV = AES_IVGen(time(NULL));
    // uint8_t* Key = AES_KeyGen256(time(NULL));

    // PrintInfo(Data, sizeof(Data), true);

    // ByteArr EncData = AES_CBC_Enc(Data, sizeof(Data), Key, IV);
    // PrintInfo(EncData.Arr, EncData.Size, false);
    
    // ByteArr DecData = AES_CBC_Dec(EncData.Arr, EncData.Size, Key, IV);
    // PrintInfo(DecData.Arr, DecData.Size, true);

    // free(EncData.Arr);
    // free(DecData.Arr);
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