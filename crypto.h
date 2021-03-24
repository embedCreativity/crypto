/*
  Copyright (C) 2021 Embed Creativity LLC

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along
  with this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>  /* for unsigned values*/
#include <stdio.h>   /* Standard input/output definitions */
#include <stdlib.h>
#include <string.h>

#ifdef WIN32
#include <winsock.h> // for ntohl
#define PACKED 
#pragma pack(push,1)
#else
#include <netinet/in.h> // for htonl, ntohl
#define PACKED __attribute__ ((__packed__))
#endif

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
} PACKED CryptoInterface_T;


#ifdef WIN32
#pragma pack(pop)
#undef PACKED
#endif

#endif // CRYPTO_H

