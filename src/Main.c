#include <stdio.h>
#include "../include/FullCrypto.h"

int main()
{
    uint8_t Data[19] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19};
    // uint8_t Data2[16] = {17, 18, 19, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13};
    uint8_t IV[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    // uint8_t IV2[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    uint8_t Key[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    ByteArr NewArr;

    // CBC is seg faulting. 
    NewArr = CBCAESEnc(Data, sizeof(Data), Key, IV);

    printf("SIZE: %lu\n", NewArr.Size);
    for (size_t i = 0; i < NewArr.Size; i++)
        printf("0x%.2X ", NewArr.Arr[i]);
        
    // Slight Memory leak here. NewArr never gets freed, as it is re-assigned.
    ByteArr NewArr2 = CBCAESDec(NewArr.Arr, 32, Key, IV);
    free(NewArr.Arr);

    printf("\nSIZE: %lu\n", NewArr2.Size);
    for (size_t i = 0; i < NewArr2.Size; i++)
        printf("0x%.2X, ", NewArr2.Arr[i]);
    printf("\n");
    free(NewArr2.Arr);

    return 0;
}
