#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>

typedef uint8_t BYTE;
typedef uint32_t WORD;

enum {
    shaSuccess = 0,
    shaNull,
    shaInputTooLong,
    shaStateError
};

#define SHA1COMPUTED (1)
#define SHA1TOOLONG  (1 << 1)

typedef struct SHA1Context{
    BYTE msg[64];
    WORD H[5];
    WORD index;
    WORD Length_High;
    WORD Length_Low;
    WORD Flag; //computed flag
}SHA1Context;

int SHA1Init(SHA1Context*);

int SHA1Update(SHA1Context*, const BYTE[], unsigned int);

int SHA1Result(SHA1Context*, BYTE[20]);



#endif /*SHA1_H*/
