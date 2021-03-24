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
  
*    Tests the Crypto code module against the three AES-128 CTR test vectors from:
*    http://tools.ietf.org/html/draft-ietf-ipsec-ciph-aes-ctr-05#page-9
*/

#include <stdint.h>     /* for unsigned values*/
#include <stdio.h>   /* Standard input/output definitions */
#ifdef WIN32
#include <mbstring.h>
#define bcmp _mbsncmp
#else
#include <string.h> /* Bcmp */
#endif
#include "crypto.h"

#define TEST_LEN_1    16
#define TEST_LEN_2    32
#define TEST_LEN_3    36

extern CryptoInterface_T cryptoIntf;

static uint8_t cryptoKey[3][16] = {
    { 0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC, 0x4B, 0xF7, 0xA5, 0x76, 0x55, 0x77, 0xF3, 0x9E },
    { 0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7, 0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63 },
    { 0x76, 0x91, 0xBE, 0x03, 0x5E, 0x50, 0x20, 0xA8, 0xAC, 0x6E, 0x61, 0x85, 0x29, 0xF9, 0xA0, 0xDC }
};

static uint8_t iv[3][16] = {
    { 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x6C, 0xB6, 0xDB, 0xC0, 0x54, 0x3B, 0x59, 0xDA, 0x48, 0xD9, 0x0B, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0xE0, 0x01, 0x7B, 0x27, 0x77, 0x7F, 0x3F, 0x4A, 0x17, 0x86, 0xF0, 0x00, 0x00, 0x00, 0x00 }
};

static uint8_t plaintext_test1[] = {
    0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62, 0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67
};

static uint8_t plaintext_test2[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

static uint8_t plaintext_test3[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23
};

static uint8_t ciphertext_test1[] = {
    0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79, 0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11, 0xB8
};

static uint8_t ciphertext_test2[] = {
    0x51, 0x04, 0xA1, 0x06, 0x16, 0x8A, 0x72, 0xD9, 0x79, 0x0D, 0x41, 0xEE, 0x8E, 0xDA, 0xD3, 0x88,
    0xEB, 0x2E, 0x1E, 0xFC, 0x46, 0xDA, 0x57, 0xC8, 0xFC, 0xE6, 0x30, 0xDF, 0x91, 0x41, 0xBE, 0x28
};

static uint8_t ciphertext_test3[] = {
    0xC1, 0xCF, 0x48, 0xA8, 0x9F, 0x2F, 0xFD, 0xD9, 0xCF, 0x46, 0x52, 0xE9, 0xEF, 0xDB, 0x72, 0xD7,
    0x45, 0x40, 0xA4, 0x2B, 0xDE, 0x6D, 0x78, 0x36, 0xD5, 0x9A, 0x5C, 0xEA, 0xAE, 0xF3, 0x10, 0x53,
    0x25, 0xB2, 0x07, 0x2F
};

int main ( void )
{
    CryptoHandle_T* pHandle;
    uint8_t output[36];

    // Start test #1
    pHandle = cryptoIntf.CreateCryptoHandle(iv[0], cryptoKey[0]);

    if ( pHandle == NULL ) {
        printf("CreateCryptoHandle failed\n");
        return 0;
    }

    cryptoIntf.Encrypt( pHandle, plaintext_test1, output, TEST_LEN_1 );
    cryptoIntf.FreeCryptoHandle(pHandle);

    if ( bcmp(output, ciphertext_test1, TEST_LEN_1) != 0 ) {
        printf("Failed test #1\n");
    } else {
        printf("Passed test #1\n");
    }

    // Start test #2
    pHandle = cryptoIntf.CreateCryptoHandle(iv[1], cryptoKey[1]);

    if ( pHandle == NULL ) {
        printf("CreateCryptoHandle failed\n");
        return 0;
    }

    cryptoIntf.Encrypt( pHandle, plaintext_test2, output, TEST_LEN_2 );
    cryptoIntf.FreeCryptoHandle(pHandle);

    if ( bcmp(output, ciphertext_test2, TEST_LEN_2) != 0 ) {
        printf("Failed test #2\n");
    } else {
        printf("Passed test #2\n");
    }

    // Start test #3
    pHandle = cryptoIntf.CreateCryptoHandle(iv[2], cryptoKey[2]);

    if ( pHandle == NULL ) {
        printf("CreateCryptoHandle failed\n");
        return 0;
    }

    cryptoIntf.Encrypt( pHandle, plaintext_test3, output, TEST_LEN_3 );
    cryptoIntf.FreeCryptoHandle(pHandle);

    if ( bcmp(output, ciphertext_test3, TEST_LEN_3) != 0 ) {
        printf("Failed test #3\n");
    } else {
        printf("Passed test #3\n");
    }

    // Start test #4 - multipart encryption
    pHandle = cryptoIntf.CreateCryptoHandle(iv[2], cryptoKey[2]);

    if ( pHandle == NULL ) {
        printf("CreateCryptoHandle failed\n");
        return 0;
    }

    // make sure the output is invalidated
    memset(output, 0, TEST_LEN_3);
    // Start encrypting and storing output, one quarter at a time
    cryptoIntf.Encrypt( pHandle, plaintext_test3, output, TEST_LEN_3/4 );
    cryptoIntf.Encrypt( pHandle, (plaintext_test3 + (TEST_LEN_3/4)), (output + (TEST_LEN_3/4)), TEST_LEN_3/4 );
    cryptoIntf.Encrypt( pHandle, (plaintext_test3 + (2*(TEST_LEN_3/4))), (output + (2*(TEST_LEN_3/4))), TEST_LEN_3/4 );
    cryptoIntf.Encrypt( pHandle, (plaintext_test3 + (3*(TEST_LEN_3/4))), (output + (3*(TEST_LEN_3/4))), TEST_LEN_3/4 );
    cryptoIntf.FreeCryptoHandle(pHandle);

    if ( bcmp(output, ciphertext_test3, TEST_LEN_3) != 0 ) {
        printf("Failed test #4\n");
    } else {
        printf("Passed test #4\n");
    }

    return 0;
}
