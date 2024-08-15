#include <stdio.h>

int main()
{   
    //* REFACTOR ALL CODE INTO C++
    // Using vectors will simplify and remove bytearr
    // Gotta learn it at some point
    // Other features (such as classes and other specific features) are extremely useful in this situation.

    // GLOBAL
    // FullCrypto.h
        // generate_iv (generate insecure IV)
        // generate_key (generate AS SECURE AS POSSIBLE list of bytes) (probably gonna suck anyway) 
        // If more than one generate_key func needed, add them to each .h

    // AES
    // aes.h (enc/dec, handles user input and error)
        // aes_ecb
        // aes_cbc
        // aes_gcm
        // aes_siv

    // aes_priv.h (private functions, do not have to handle user error)
        // aes_std (enc/dec) (Plaintext[16], Key[128/192/256 bit])
        // aes_
    return 0;
}