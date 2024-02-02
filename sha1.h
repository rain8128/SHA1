#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>

typedef uint8_t BYTE;
typedef uint32_t WORD;

// typedef struct SHA1Ctx{

// }SHA1Ctx;

void SHA1(const BYTE buf[], unsigned int length, BYTE digest[20]);



#endif /*SHA1_H*/