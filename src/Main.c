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
    uint8_t Plaintext[] = {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t AAD[] = "AAD TEST DATA";
    uint8_t Key[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t IV[] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Plaintext (32 bytes) =      01000000000000000000000000000000
//                                02000000000000000000000000000000
//    AAD (0 bytes) =
//    Key =                       01000000000000000000000000000000
//                                00000000000000000000000000000000
//    Nonce =                     030000000000000000000000
//    Record authentication key = b5d3c529dfafac43136d2d11be284d7f
//    Record encryption key =     b914f4742be9e1d7a2f84addbf96dec3
//                                456e3c6c05ecc157cdbf0700fedad222
//    POLYVAL input =             01000000000000000000000000000000
//                                02000000000000000000000000000000
//                                00000000000000000001000000000000
//    POLYVAL result =            899b6381b3d46f0def7aa0517ba188f5
//    POLYVAL result XOR nonce =  8a9b6381b3d46f0def7aa0517ba188f5
//    ... and masked =            8a9b6381b3d46f0def7aa0517ba18875
//    Tag =                       e819e63abcd020b006a976397632eb5d
//    Initial counter =           e819e63abcd020b006a976397632ebdd                   April 2019

//    Result (48 bytes) =         4a6a9db4c8c6549201b9edb53006cba8
//                                21ec9cf850948a7c86c68ac7539d027f
//                                e819e63abcd020b006a976397632eb5d



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
