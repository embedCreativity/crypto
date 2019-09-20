/*
*    This is a counter wrapper around Gladman's AES engine.  This interface removes much of the detail
*    involved in the underlying crypto implementation and leaves a simple clean interface.
*
*    History:
*        January 10, 2011:  created
*/

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>  /* for unsigned values*/
#include <stdio.h>   /* Standard input/output definitions */
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h> // for htonl, ntohl

#define IV_LEN     16
#define KEY_LEN 16

typedef void* CryptoHandle_T;

/*     CreateCryptoHandle()
*      input params:
*        uint8_t* pIV
*        uint8_t* pKey
*
*    return CryptoHandle_T*
*        NULL if allocation failed
*/
typedef CryptoHandle_T* (*CreateCryptoHandle_T) (
    const uint8_t* pIV,
    const uint8_t* pKey );

/*     FreeCryptoHandle()
*      input params:
*        CryptoHandle_T* pHandle;
*
*/
typedef void (*FreeCryptoHandle_T) (
    CryptoHandle_T* pHandle);

/*     Encrypt()
*      input params:
*        CryptoHandle_T* pHandle
*        uint8_t* pPlainText - input plain text buffer
*        uint8_t* pCipherText - pre-allocated output buffer
*        uint32_t count - number of bytes to be encrypted
*/
typedef void (*Encrypt_T) (
    CryptoHandle_T* pHandle,
    uint8_t* pPlainText,
    uint8_t* pCipherText,
    uint32_t count );

/*     Decrypt()
*      input params:
*        CryptoHandle_T* pHandle
*        uint8_t* pCipherText - input ciphertext buffer
*        uint8_t* pPlainText - pre-allocated output buffer
*        uint32_t count - number of bytes to be decrypted
*/
typedef void (*Decrypt_T) (
    CryptoHandle_T* pHandle,
    uint8_t* pCipherText,
    uint8_t* pPlainText,
    uint32_t count );

// This is the Crypto interface
typedef struct _CryptoInterface_T {
    CreateCryptoHandle_T CreateCryptoHandle;
    FreeCryptoHandle_T FreeCryptoHandle;
    Encrypt_T Encrypt;
    Decrypt_T Decrypt;
} __attribute__((__packed__)) CryptoInterface_T;

#endif // CRYPTO_H

