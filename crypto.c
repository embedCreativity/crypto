/*
*    This is a counter wrapper around Gladman's AES engine.  This interface removes much of the detail
*    involved in the underlying crypto implementation and leaves a simple clean interface.
*
*    History:
*        January 10, 2011:  created
*/

#include "crypto.h"

/********************************************************/
/* Content stripped from Gladman's aes.h file           */
#define N_ROW                   4
#define N_COL                   4
#define N_BLOCK   (N_ROW * N_COL)
#define N_MAX_ROUNDS           14

typedef uint8_t return_type;
typedef uint8_t length_type;

typedef struct
{   uint8_t ksch[(N_MAX_ROUNDS + 1) * N_BLOCK];
    uint8_t rnd;
} aes_context;

static return_type aes_set_key( const uint8_t *key,
                         length_type keylen,
                         aes_context ctx[1] );

static return_type aes_encrypt( const uint8_t in[N_BLOCK],
                         uint8_t out[N_BLOCK],
                         const aes_context ctx[1] );
/********************************************************/
/* Content stripped from Gladman's aes.c file           */

/* functions for finite field multiplication in the AES Galois field    */
#define WPOLY   0x011b
#define f1(x)   (x)
#define f2(x)   ((x << 1) ^ (((x >> 7) & 1) * WPOLY))
#define f3(x)   (f2(x) ^ x)

#define sb_data(w) {    /* S Box data values */                            \
    w(0x63), w(0x7c), w(0x77), w(0x7b), w(0xf2), w(0x6b), w(0x6f), w(0xc5),\
    w(0x30), w(0x01), w(0x67), w(0x2b), w(0xfe), w(0xd7), w(0xab), w(0x76),\
    w(0xca), w(0x82), w(0xc9), w(0x7d), w(0xfa), w(0x59), w(0x47), w(0xf0),\
    w(0xad), w(0xd4), w(0xa2), w(0xaf), w(0x9c), w(0xa4), w(0x72), w(0xc0),\
    w(0xb7), w(0xfd), w(0x93), w(0x26), w(0x36), w(0x3f), w(0xf7), w(0xcc),\
    w(0x34), w(0xa5), w(0xe5), w(0xf1), w(0x71), w(0xd8), w(0x31), w(0x15),\
    w(0x04), w(0xc7), w(0x23), w(0xc3), w(0x18), w(0x96), w(0x05), w(0x9a),\
    w(0x07), w(0x12), w(0x80), w(0xe2), w(0xeb), w(0x27), w(0xb2), w(0x75),\
    w(0x09), w(0x83), w(0x2c), w(0x1a), w(0x1b), w(0x6e), w(0x5a), w(0xa0),\
    w(0x52), w(0x3b), w(0xd6), w(0xb3), w(0x29), w(0xe3), w(0x2f), w(0x84),\
    w(0x53), w(0xd1), w(0x00), w(0xed), w(0x20), w(0xfc), w(0xb1), w(0x5b),\
    w(0x6a), w(0xcb), w(0xbe), w(0x39), w(0x4a), w(0x4c), w(0x58), w(0xcf),\
    w(0xd0), w(0xef), w(0xaa), w(0xfb), w(0x43), w(0x4d), w(0x33), w(0x85),\
    w(0x45), w(0xf9), w(0x02), w(0x7f), w(0x50), w(0x3c), w(0x9f), w(0xa8),\
    w(0x51), w(0xa3), w(0x40), w(0x8f), w(0x92), w(0x9d), w(0x38), w(0xf5),\
    w(0xbc), w(0xb6), w(0xda), w(0x21), w(0x10), w(0xff), w(0xf3), w(0xd2),\
    w(0xcd), w(0x0c), w(0x13), w(0xec), w(0x5f), w(0x97), w(0x44), w(0x17),\
    w(0xc4), w(0xa7), w(0x7e), w(0x3d), w(0x64), w(0x5d), w(0x19), w(0x73),\
    w(0x60), w(0x81), w(0x4f), w(0xdc), w(0x22), w(0x2a), w(0x90), w(0x88),\
    w(0x46), w(0xee), w(0xb8), w(0x14), w(0xde), w(0x5e), w(0x0b), w(0xdb),\
    w(0xe0), w(0x32), w(0x3a), w(0x0a), w(0x49), w(0x06), w(0x24), w(0x5c),\
    w(0xc2), w(0xd3), w(0xac), w(0x62), w(0x91), w(0x95), w(0xe4), w(0x79),\
    w(0xe7), w(0xc8), w(0x37), w(0x6d), w(0x8d), w(0xd5), w(0x4e), w(0xa9),\
    w(0x6c), w(0x56), w(0xf4), w(0xea), w(0x65), w(0x7a), w(0xae), w(0x08),\
    w(0xba), w(0x78), w(0x25), w(0x2e), w(0x1c), w(0xa6), w(0xb4), w(0xc6),\
    w(0xe8), w(0xdd), w(0x74), w(0x1f), w(0x4b), w(0xbd), w(0x8b), w(0x8a),\
    w(0x70), w(0x3e), w(0xb5), w(0x66), w(0x48), w(0x03), w(0xf6), w(0x0e),\
    w(0x61), w(0x35), w(0x57), w(0xb9), w(0x86), w(0xc1), w(0x1d), w(0x9e),\
    w(0xe1), w(0xf8), w(0x98), w(0x11), w(0x69), w(0xd9), w(0x8e), w(0x94),\
    w(0x9b), w(0x1e), w(0x87), w(0xe9), w(0xce), w(0x55), w(0x28), w(0xdf),\
    w(0x8c), w(0xa1), w(0x89), w(0x0d), w(0xbf), w(0xe6), w(0x42), w(0x68),\
    w(0x41), w(0x99), w(0x2d), w(0x0f), w(0xb0), w(0x54), w(0xbb), w(0x16) }

static const uint8_t sbox[256]  =  sb_data(f1);
static const uint8_t gfm2_sbox[256] = sb_data(f2);
static const uint8_t gfm3_sbox[256] = sb_data(f3);

#define s_box(x)     sbox[(x)]
#define gfm2_sb(x)   gfm2_sbox[(x)]
#define gfm3_sb(x)   gfm3_sbox[(x)]
#define block_copy_nn(d, s, l)    memcpy(d, s, l)
#define block_copy(d, s)          memcpy(d, s, N_BLOCK)

static void xor_block( void *d, const void *s )
{
    ((uint32_t*)d)[ 0] ^= ((uint32_t*)s)[ 0];
    ((uint32_t*)d)[ 1] ^= ((uint32_t*)s)[ 1];
    ((uint32_t*)d)[ 2] ^= ((uint32_t*)s)[ 2];
    ((uint32_t*)d)[ 3] ^= ((uint32_t*)s)[ 3];
}

static void copy_and_key( void *d, const void *s, const void *k )
{
    ((uint32_t*)d)[ 0] = ((uint32_t*)s)[ 0] ^ ((uint32_t*)k)[ 0];
    ((uint32_t*)d)[ 1] = ((uint32_t*)s)[ 1] ^ ((uint32_t*)k)[ 1];
    ((uint32_t*)d)[ 2] = ((uint32_t*)s)[ 2] ^ ((uint32_t*)k)[ 2];
    ((uint32_t*)d)[ 3] = ((uint32_t*)s)[ 3] ^ ((uint32_t*)k)[ 3];
}

static void add_round_key( uint8_t d[N_BLOCK], const uint8_t k[N_BLOCK] )
{
    xor_block(d, k);
}

static void shift_sub_rows( uint8_t st[N_BLOCK] )
{
    uint8_t tt;

    st[ 0] = s_box(st[ 0]); st[ 4] = s_box(st[ 4]);
    st[ 8] = s_box(st[ 8]); st[12] = s_box(st[12]);

    tt = st[1]; st[ 1] = s_box(st[ 5]); st[ 5] = s_box(st[ 9]);
    st[ 9] = s_box(st[13]); st[13] = s_box( tt );

    tt = st[2]; st[ 2] = s_box(st[10]); st[10] = s_box( tt );
    tt = st[6]; st[ 6] = s_box(st[14]); st[14] = s_box( tt );

    tt = st[15]; st[15] = s_box(st[11]); st[11] = s_box(st[ 7]);
    st[ 7] = s_box(st[ 3]); st[ 3] = s_box( tt );
}

static void mix_sub_columns( uint8_t dt[N_BLOCK] )
{
     uint8_t st[N_BLOCK];

    block_copy(st, dt);
    dt[ 0] = gfm2_sb(st[0]) ^ gfm3_sb(st[5]) ^ s_box(st[10]) ^ s_box(st[15]);
    dt[ 1] = s_box(st[0]) ^ gfm2_sb(st[5]) ^ gfm3_sb(st[10]) ^ s_box(st[15]);
    dt[ 2] = s_box(st[0]) ^ s_box(st[5]) ^ gfm2_sb(st[10]) ^ gfm3_sb(st[15]);
    dt[ 3] = gfm3_sb(st[0]) ^ s_box(st[5]) ^ s_box(st[10]) ^ gfm2_sb(st[15]);

    dt[ 4] = gfm2_sb(st[4]) ^ gfm3_sb(st[9]) ^ s_box(st[14]) ^ s_box(st[3]);
    dt[ 5] = s_box(st[4]) ^ gfm2_sb(st[9]) ^ gfm3_sb(st[14]) ^ s_box(st[3]);
    dt[ 6] = s_box(st[4]) ^ s_box(st[9]) ^ gfm2_sb(st[14]) ^ gfm3_sb(st[3]);
    dt[ 7] = gfm3_sb(st[4]) ^ s_box(st[9]) ^ s_box(st[14]) ^ gfm2_sb(st[3]);

    dt[ 8] = gfm2_sb(st[8]) ^ gfm3_sb(st[13]) ^ s_box(st[2]) ^ s_box(st[7]);
    dt[ 9] = s_box(st[8]) ^ gfm2_sb(st[13]) ^ gfm3_sb(st[2]) ^ s_box(st[7]);
    dt[10] = s_box(st[8]) ^ s_box(st[13]) ^ gfm2_sb(st[2]) ^ gfm3_sb(st[7]);
    dt[11] = gfm3_sb(st[8]) ^ s_box(st[13]) ^ s_box(st[2]) ^ gfm2_sb(st[7]);

    dt[12] = gfm2_sb(st[12]) ^ gfm3_sb(st[1]) ^ s_box(st[6]) ^ s_box(st[11]);
    dt[13] = s_box(st[12]) ^ gfm2_sb(st[1]) ^ gfm3_sb(st[6]) ^ s_box(st[11]);
    dt[14] = s_box(st[12]) ^ s_box(st[1]) ^ gfm2_sb(st[6]) ^ gfm3_sb(st[11]);
    dt[15] = gfm3_sb(st[12]) ^ s_box(st[1]) ^ s_box(st[6]) ^ gfm2_sb(st[11]);
}

static return_type aes_set_key( const uint8_t *key, length_type keylen, aes_context ctx[1] )
{
    uint8_t cc, rc, hi;

    if ( keylen != 16 ) {
        ctx->rnd = 0;
        return -1;
    }

    block_copy_nn(ctx->ksch, key, keylen);
    hi = (keylen + 28) << 2;
    ctx->rnd = (hi >> 4) - 1;
    for( cc = keylen, rc = 1; cc < hi; cc += 4 )
    {   uint8_t tt, t0, t1, t2, t3;

        t0 = ctx->ksch[cc - 4];
        t1 = ctx->ksch[cc - 3];
        t2 = ctx->ksch[cc - 2];
        t3 = ctx->ksch[cc - 1];
        if( cc % keylen == 0 )
        {
            tt = t0;
            t0 = s_box(t1) ^ rc;
            t1 = s_box(t2);
            t2 = s_box(t3);
            t3 = s_box(tt);
            rc = f2(rc);
        }
        else if( keylen > 24 && cc % keylen == 16 )
        {
            t0 = s_box(t0);
            t1 = s_box(t1);
            t2 = s_box(t2);
            t3 = s_box(t3);
        }
        tt = cc - keylen;
        ctx->ksch[cc + 0] = ctx->ksch[tt + 0] ^ t0;
        ctx->ksch[cc + 1] = ctx->ksch[tt + 1] ^ t1;
        ctx->ksch[cc + 2] = ctx->ksch[tt + 2] ^ t2;
        ctx->ksch[cc + 3] = ctx->ksch[tt + 3] ^ t3;
    }
    return 0;
}

/*  Encrypt a single block of 16 bytes */
static return_type aes_encrypt( const uint8_t in[N_BLOCK], uint8_t  out[N_BLOCK], const aes_context ctx[1] )
{
    if( ctx->rnd )
    {
        uint8_t s1[N_BLOCK], r;
        copy_and_key( s1, in, ctx->ksch );

        for( r = 1 ; r < ctx->rnd ; ++r )
        {
            mix_sub_columns( s1 );
            add_round_key( s1, ctx->ksch + r * N_BLOCK);
        }
        shift_sub_rows( s1 );
        copy_and_key( out, s1, ctx->ksch + r * N_BLOCK );
    }
    else
        return -1;
    return 0;
}

/********************************************************
* AES-128 CTR Wrapper implementation
*********************************************************/

typedef struct _CryptoData_T {
    uint8_t IV[N_BLOCK];
    uint8_t Key[N_BLOCK];
    uint32_t counter;
    aes_context ctx;
} __attribute__ ((__packed__)) CryptoData_T;

static void generate_crypto_pad (
    CryptoData_T* pHandle,
    uint32_t index,
    uint8_t* pPad)
{
    uint32_t blockNumber = (index/N_BLOCK)+1; // block number is not zero-based (starts at 1)
    uint8_t prepad[N_BLOCK];
    uint32_t* p32; // I hate naming variables
    uint32_t i;

    // create pre-encrypted pad using the IV and counter value
    for ( i = 0; i < N_BLOCK; i++ ) {
        prepad[i] = pHandle->IV[i];
    }
    // xor the block number into the prepad
    p32 = (uint32_t*)&prepad[N_BLOCK - sizeof(uint32_t)]; // set pointer into buffer
    *p32 = *p32 ^ (htonl(blockNumber)); // xor the contents of the buffer with the counter value

    if ( aes_encrypt( prepad, pPad, &pHandle->ctx ) != 0 ) {
        printf("encrypt() failed\n");
    }
}

static void aes_ctr_encrypt (
    CryptoData_T* pHandle,
    uint8_t* in,
    uint8_t* out,
    uint32_t index,
    uint32_t count)
{
    uint8_t pad[N_BLOCK];
    uint32_t i;

    // init variables
    generate_crypto_pad(pHandle, index, pad);

    for ( i = 0; i < count; ) {
        // xor input data against pad
        *out = *in ^ pad[(index + i) % N_BLOCK];
        i += 1;
        out++; // advance pointer
        in++; // advance pointer
        // check if we need to whip up a fresh pad
        if ( ((index + i) % N_BLOCK) == 0 ) {
            generate_crypto_pad(pHandle, (index + i), pad);
        }
    }
}

static CryptoHandle_T* CreateCryptoHandle (
    const uint8_t* pIV,
    const uint8_t* pKey )
{
    CryptoData_T* pHandle;
    uint8_t i;

    pHandle = (CryptoData_T*)malloc(sizeof(CryptoData_T));
    // check for malloc fail or bad input parameters
    if ( (pKey == NULL) || (pIV == NULL) || (pHandle == NULL) ) {
        return NULL;
    }

    // set up structure
    pHandle->counter = 0;
    if ( aes_set_key(pKey, N_BLOCK, &pHandle->ctx) != 0     ) {
        return NULL;
    }
    for ( i = 0; i < N_BLOCK; i++ ) {
        pHandle->IV[i] = pIV[i];
        pHandle->Key[i] = pKey[i];
    }

    return (CryptoHandle_T*)pHandle;
} // end CreateCryptoHandle

static void FreeCryptoHandle (
    CryptoHandle_T* pHandle)
{
    free(pHandle);
    pHandle = NULL;
}

static void Encrypt (
    CryptoHandle_T* pHandle,
    uint8_t* pPlainText,
    uint8_t* pCipherText,
    uint32_t count )
{
     aes_ctr_encrypt (
        (CryptoData_T*)pHandle,
        pPlainText,
        pCipherText,
        ((CryptoData_T*)pHandle)->counter,
        count);

    // update handle
    ((CryptoData_T*)pHandle)->counter = ((CryptoData_T*)pHandle)->counter + count;
}

static void Decrypt (
    CryptoHandle_T* pHandle,
    uint8_t* pCipherText,
    uint8_t* pPlainText,
    uint32_t count )
{
     aes_ctr_encrypt (
        (CryptoData_T*)pHandle,
        pCipherText,
        pPlainText,
        ((CryptoData_T*)pHandle)->counter,
        count);

    // update handle
    ((CryptoData_T*)pHandle)->counter = ((CryptoData_T*)pHandle)->counter + count;
}

// this is the exported Crypto interface
CryptoInterface_T cryptoIntf = {
    CreateCryptoHandle,
    FreeCryptoHandle,
    Encrypt,
    Decrypt
};

