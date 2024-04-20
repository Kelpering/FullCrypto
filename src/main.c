#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include "../include/bytearr.h"
#include "../include/error.h"
#include "../include/aes.h"
#include "../include/base64.h"
#include "../include/hash.h"
#include "../include/rsa.h"

void PrintInfo(uint8_t* Array, size_t Size, bool isString);
void StrToHex(char *Str);

int main()
{   
    //^ TODO
    //^ Refactor code to look nice (Reprogram the entire thing)
    //* Add error detection / reporting (Malloc, failure to encrypt/decrypt, etc).
    //* Standardize function I/O
    //^ Fix all Endian aligned data manip to be compatible cross platform.
    //^ Document / Re-document code

    //^ Reprogram a majority of AES to be more standard and meet current code expectations.

    //^ Function and function naming
    //* Standardize function returns and inputs
        //* ErrorCode c_snake_case(non, struct, vars, unless prev set [RSAKey])
    //* For variable size arrays, use &ByteArr (malloc Arr and Size) in params (last)
    //* For fixed size arrays, use Arr[Size] and expect user to pre-allocate (no OoB check)
    //* Error codes: typedef enum, 0 for success, 1 for false (inverse bool), extras in future.
    //* Names: FILE_TYPE_OPERATION (Ex. aes_std_enc for aes.c standard encrypt)
    //* add error checking to all important functions. Quick error checking (if false then exit w/ error)
    //* enums will either account for specific errors (malloc error) or non specific (1)
        //* This allows for error checking to be nonspecific (if function -> error, else 0 good)

    //^ User implementation
    //* Expect user to be knowledgable and use correctly.
    //* Functions with additional expectations (E.g. RSA Mod < Key length)
        //* are ignored and assumed to be followed (Crypto breaks are ignored, code breaks are addressed)
    //* In future (RFC in func name) will address these concerns and implement further error codes to report issues.

    //^ Documentation and file naming
    //* Each .c file will share a .h file for implementation. If Private .h is required, name = NAME_private.h
    //* Highlight usage (hover over function) will be implemented in header. All functions will require descriptions of variables along with appropriate names
    //* Every .h public file will have an associated .md README file for extensive usage descriptions (examples, usage, safe/unsafe, etc). (AES.md should be a good example for now)
    //* Extra README (Licenses.md) will include all licensed libraries used, along with files and locations. include licenses in README.md at the bottom, no locations, just libs.
    //* Describe all necessary info in the doxygen function comments & README
    //* Describe the process in the function itself
    //* Use comment colors as such:
    //      Standard description comments
    //*     Specific / general purpose similar to standard //
    //!     Use for important or deprecated (such as malloc)
    //^     TODO code
    //?     sections of code (like functions). Header comment

    //^ Data storage and manip (Host Endianness)
    //* uint's should not matter unless being used to store data.
    //* All data storage should be byte-by-byte, not in larger uints, unless arithemtic is performed
    //* arithmetic should not matter to endianness unless the input/output is undefined
    //* All numbers larger than a byte should be stored in byte-sized Little Endian format.
    //? Big-endian =    Most->Least    Hundreds->Tens->Ones
    //? Little-endian = Least->Most    Ones->Tens->Hundreds
    //* If not a number, but a data structure, endian should not matter.
    //^ Rewrite all of hash, very endian dependent, also looks awful

    //^ Misc
    //* Remove pragma once and replace with standard include guard
    //* Typedefs are PascalCase
    //* Variables are all PascalCase (they look neat)

    //? Playground

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

//! Awful code used only for testing, probably leaks and destroys memory OoB, use in seperate runs exclusively for converting to hex strings.
void StrToHex(char *Str)
{
    size_t Count = 0;
    while (Str[Count++] != '\0');

    char *HexStr = malloc((Count<<1) + Count - 2);

    for (size_t i = 0, j=0; i < Count-2; i+=2, j+=6)
    {
        HexStr[j+0] = '0';
        HexStr[j+1] = 'x';
        HexStr[j+2] = Str[i];
        HexStr[j+3] = Str[i+1];
        HexStr[j+4] = ',';
        HexStr[j+5] = ' ';
    }
    HexStr[(Count<<1) + Count - 3] = '\0';
    printf("%s\n", HexStr);
    free(HexStr);

    return;
}