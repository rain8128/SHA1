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

void SHA1Process(SHA1Context*);

int SHA1Init(SHA1Context* Ctx){
    Ctx->Length_Low  = 0;
    Ctx->Length_High = 0;
    Ctx->index       = 0;

    Ctx->H[0] = 0x67452301;
    Ctx->H[1] = 0xEFCDAB89;
    Ctx->H[2] = 0x98BADCFE;
    Ctx->H[3] = 0x10325476;
    Ctx->H[4] = 0xC3D2E1F0;

    Ctx->Flag = 0;
    return shaSuccess;
}

int SHA1Update(SHA1Context* Ctx,const BYTE buf[], unsigned int length){
    
    if(length == 0){
        return shaSuccess;
    }

    if(!Ctx || !buf){
        return shaNull;
    }

    if(Ctx->Flag){
        return shaStateError;
    }

    while(length--){
        Ctx->msg[Ctx->index++] = *buf++ & 0xFF;
        Ctx->Length_Low += 8;

        if(Ctx->Length_Low == 0){
            Ctx->Length_High++;
            if(Ctx->Length_High == 0){
                Ctx->Flag |= SHA1TOOLONG;
            }
        }

        if(Ctx->index == 64){
            SHA1Process(Ctx);
        }
    }
    return shaSuccess;
}

void SHA1Process(SHA1Context* Ctx){
    WORD W[80];
    for(int i = 0; i < 16; i++){
        W[i] = Ctx->msg[i*4  ] << 24
             | Ctx->msg[i*4+1] << 16
             | Ctx->msg[i*4+2] << 8
             | Ctx->msg[i*4+3];
    }

    for(int t = 16; t < 80; t++){
        W[t] = ROL(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16],1);
    }

    WORD TEMP;
    WORD A = Ctx->H[0];
    WORD B = Ctx->H[1];
    WORD C = Ctx->H[2];
    WORD D = Ctx->H[3];
    WORD E = Ctx->H[4];

    for(int t = 0; t < 80; t++){
        TEMP = ROL(A,5) + f(t, B, C, D) + E + W[t] + K(t);
        E = D;
        D = C;
        C = ROL(B,30);
        B = A;
        A = TEMP;
    }

    Ctx->H[0] += A;
    Ctx->H[1] += B;
    Ctx->H[2] += C;
    Ctx->H[3] += D;
    Ctx->H[4] += E;

    Ctx->index = 0;
}

int SHA1Result(SHA1Context* Ctx, BYTE digest[20]){

    if(!Ctx || !digest){
        return shaNull;
    }

    if(!(Ctx->Flag & SHA1COMPUTED)){
        Ctx->msg[Ctx->index++] = 0x80;

        if(Ctx->index > 56){
            while(Ctx->index < 64){
                Ctx->msg[Ctx->index++] = 0;
            }   
            SHA1Process(Ctx);
        }

        while(Ctx->index < 56){
            Ctx->msg[Ctx->index++] = 0;
        }

        Ctx->msg[56] = Ctx->Length_High >> 24;
        Ctx->msg[57] = Ctx->Length_High >> 16;
        Ctx->msg[58] = Ctx->Length_High >> 8;
        Ctx->msg[59] = Ctx->Length_High;
        Ctx->msg[60] = Ctx->Length_Low >> 24;
        Ctx->msg[61] = Ctx->Length_Low >> 16;
        Ctx->msg[62] = Ctx->Length_Low >> 8;
        Ctx->msg[63] = Ctx->Length_Low;

        SHA1Process(Ctx);
        Ctx->Flag |= SHA1COMPUTED;
    }

    for(int i = 0; i < 20; i++){
        digest[i] = Ctx->H[i/4] >> ((3 - (i % 4)) * 8);
    }

    return shaSuccess;
}