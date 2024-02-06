#include <stdio.h>
#include "../include/FullCrypto.h"

int main()
{
    uint8_t Data[19] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19};
    uint8_t Key[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    ByteArr NewArr;

    NewArr = ECBAESEnc(Data, 19, Key);

    NewArr = ECBAESDec(NewArr.Arr, NewArr.Size, Key);

    for (int i = 0; i < NewArr.Size; i++)
        printf("0x%d, ", NewArr.Arr[i]);
    printf("\n");

    return 0;
}