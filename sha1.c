#include "sha1.h"

#define ROL(x,n) (((x) << (n)) | ((x) >> (32-(n))))

WORD f(int t, WORD B, WORD C, WORD D){
    switch (t/20){
        case 0:
            return (B & C) | ((~B) & D);
            break;

        case 1:
        case 3:
            return B ^ C ^ D;
            break;

        case 2:
            return (B & C) | (B & D) | (C & D);
            break;
        default:
            break;
    }
}

WORD K(int t){
    WORD ret;
    switch (t/20){
        case 0:
            ret = 0x5A827999;
            break;

        case 1:
            ret = 0x6ED9EBA1;
            break;

        case 2:
            ret = 0x8F1BBCDC;
            break;

        case 3:
            ret = 0xCA62C1D6;
            break;
        
        default:
            break;
    }
    return ret;
}

void SHA1(const BYTE buf[], unsigned int length, BYTE output[20]){
    if(length > 64 - 9){
        output = NULL;
        return;
    }

    BYTE msg[64] = {0};
    for(int i = 0; i < length; i++){
        msg[i] = buf[i];
    }
    msg[length] = 0x80;

    length *= 8;
    for(int i = 0; i < 4; i++){
        msg[63-i] = length >> (i * 8);
    }

    WORD H[5];
    H[0] = 0x67452301;
    H[1] = 0xEFCDAB89;
    H[2] = 0x98BADCFE;
    H[3] = 0x10325476;
    H[4] = 0xC3D2E1F0;

    WORD W[80] = {0};
    for(int i = 0; i < 64; i++){
        W[i/4] |= msg[i] << ((3 - (i % 4)) * 8);
    }

    for(int t = 16; t < 80; t++){
        W[t] = ROL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16],1);
    }

    WORD TEMP;
    WORD A = H[0];
    WORD B = H[1];
    WORD C = H[2];
    WORD D = H[3];
    WORD E = H[4];

    for(int t = 0; t < 80; t++){
        TEMP = ROL(A,5) + f(t, B, C, D) + E + W[t] + K(t);
        E = D;
        D = C;
        C = ROL(B,30);
        B = A;
        A = TEMP;
    }

    H[0] += A;
    H[1] += B;
    H[2] += C;
    H[3] += D;
    H[4] += E;

    for(int i = 0; i < 20; i++){
        output[i] = H[i/4] >> ((3 - (i % 4)) * 8);
    }
}