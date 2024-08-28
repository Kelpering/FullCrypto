# Newer plan

### Take this project and refactor, with better safety and library-esque structure.
- Public (safe) functions
- Private (unsafe) functions that will be more susceptible to misuse, but much less strict.
- Global standards (specifically with error checking and handling)
- Better name
- Full rewrite of README.md and probably smaller Manual.md for each section of library (AES.md, Base64.md, etc)

### Desired additions
- NO external libraries. All code will be my own
    - Current external libraries:
    - GMP (Gnu Mulitple Precision Library)
- bignum library (for public key)
- security standards (secure up to but not including side-channel attacks)
- unit testing (test functions with set parameters and outputs)
- global data transfer/translate library (e.g. byte -> base64)
- data storage standards (RSA key storage, encrypted file storage, etc)
- data interaction standard (Encrypt specific files with specific protocols, should be applicable to all protocols)