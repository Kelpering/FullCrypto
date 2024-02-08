#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include "../include/FullCrypto.h"

void PrintInfo(uint8_t* Array, size_t Size, bool isString);

int main()
{
    uint8_t Data[] = "HELLO WORLD!";
    uint8_t* IV = IVGen(time(NULL));
    uint8_t* Key = AESKeyGen256(time(NULL));

    PrintInfo(Data, sizeof(Data), true);

    ByteArr EncData = CBCAESEnc(Data, sizeof(Data), Key, IV);
    PrintInfo(EncData.Arr, EncData.Size, false);
    
    ByteArr DecData = CBCAESDec(EncData.Arr, EncData.Size, Key, IV);
    PrintInfo(DecData.Arr, DecData.Size, true);

    free(EncData.Arr);
    free(DecData.Arr);
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
