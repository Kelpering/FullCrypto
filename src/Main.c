#include <stdio.h>
#include "../include/FullCrypto.h"

int main()
{
    uint8_t Data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11};
    uint8_t IV[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t Key[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};

    printf("\nSize: %d\n", sizeof(Data));
    for (size_t i = 0; i < sizeof(Data); i++)
        printf("0x%.2X ", Data[i]);
    printf("\n\n");

    ByteArr NewArr = CBCAESEnc(Data, sizeof(Data), Key, IV);

    printf("SIZE: %lu\n", NewArr.Size);
    for (size_t i = 0; i < NewArr.Size; i++)
        printf("0x%.2X ", NewArr.Arr[i]);
    printf("\n");
    
    ByteArr NewArr2 = CBCAESDec(NewArr.Arr, NewArr.Size, Key, IV);
    free(NewArr.Arr);

    printf("\nSIZE: %lu\n", NewArr2.Size);
    for (size_t i = 0; i < NewArr2.Size; i++)
        printf("0x%.2X ", NewArr2.Arr[i]);
    printf("\n");
    free(NewArr2.Arr);

    return 0;
}
