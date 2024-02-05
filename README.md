SHA-1
=====
An implementation of the SHA-1 hash algorithm in C.

# Reference

#### SHA1Init

```C
int SHA1Init(SHA1Context* Ctx);
```

Call this before calling other function to init `Ctx`.

#### SHA1Update

```C
int SHA1Update(SHA1Context* Ctx, const BYTE buf[], unsigned int length);
```

This function accepts an array of octets `buf` as the next portion of the message. `length` is the length of `buf`.

#### SHA1Result

```C
int SHA1Result(SHA1Context* Ctx, BYTE digest[20])
```
Computes the message digest and stores to `digest`.
