# MD5

A project written entirely in C, designed to be an MD5 implementation. Converts any length and type of data into a hexadecimal string of exact length.

## Methods

### HashMD5()

Hashes a variable amount of data with the MD5 standard. Returns a 16 byte hash as a hexadecimal string.

```C
int main()
{
    uint8_t Data[] = {1, 2, 3, 4, 5};   // Data can be of any type and length.
    char StringHash[33];    // StringHash is a string of size 33, which stores the end hash in hexadecimal.
    
    // Pass the Data array (any type), the size of the array in bytes, and the char* to store the Hash in.
    HashMD5(Data, sizeof(Data), StringHash);

    printf("StringHash Returned: %s", StringHash);
    return 0;
}
```
