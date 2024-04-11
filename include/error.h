#ifndef ERROR_H
#define ERROR_H

typedef enum
{
    success = 0,
    unknown_error = 1,
    malloc_error = 2,
} ErrorCode;

#endif // ERROR_H