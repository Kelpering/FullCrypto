#ifndef ERROR_H
#define ERROR_H

/// @brief A struct to describe errors returned from all API and some non public functions.
/// @param success The operation performed successfully, assume all outputs are valid.
/// @param unknown_error The error is expected but does not have a set ErrorCode element. Assume outputs are undefined or as stated in documentation.
/// @param malloc_error The error was caused because an allocation function returned NULL or error. Assume both unknown_error and that any output allocations are freed.
/// @param length_error The error is caused because one or more of the parameters did not match the legnth requirements. Check the documentation for details and assume unknown_error.
typedef enum
{
    success = 0,
    unknown_error = 1,
    malloc_error = 2,
    length_error = 3,
} ErrorCode;

#endif // ERROR_H