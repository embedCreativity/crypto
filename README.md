# Crypto
Small and Simple AES-CTR 128-bit Wrapper

## Usage
The Makefile can be modified to produce an installable library for your system. The lines that will do this are currently commented out. Switch around the active lines with the ones that are commented out. Currently, the AES implementation is simply compiled into an object file to be used with your application. Please refer to the test application that verifies the ciphertext produced by the library.

## API
The AES implementation is used in your system as a pseudo-C++ encapsulated object by sticking it in a struct. Refer to the test application again for this one. Simply have a global variable declared as follows:

```c
extern CryptoInterface_T cryptoIntf;
```

Use the interface as follows:
```c
// Pointer to handle that maintains state of the internals
CryptoHandle_T* pHandle;

// Allocate memory for the interface
pHandle = cryptoIntf.CreateCryptoHandle(<pointer to initialization vector>, <pointer to your key>);

// Encrypt plaintext and store ciphertext in output buffer
cryptoIntf.Encrypt( pHandle, <pointer to plaintext data>, <pointer to output buffer>, <length of data>);

// Clean up
cryptoIntf.FreeCryptoHandle(pHandle);
```

This can also be done in a multipart process if you want to encrypt a large file and do not want to allocate one massive buffer to store the contents of the file in memory.

```c
// Pointer to handle that maintains state of the internals
CryptoHandle_T* pHandle;

// Allocate memory for the interface
pHandle = cryptoIntf.CreateCryptoHandle(<pointer to initialization vector>, <pointer to your key>);

// Encrypt data in chunks
cryptoIntf.Encrypt( pHandle, <pointer to start of plaintext data>, <pointer to start of output buffer>, <length of your read buffer>);

// Advance pointers in input and output buffers. Maintain length until your final read/write cycle for the remainder
cryptoIntf.Encrypt( pHandle, <pointer + offset>, <pointer + offset>, <length of your read buffer>);

// Do that in a loop until final read/write - adjust length for remaining bytes

// Clean up
cryptoIntf.FreeCryptoHandle(pHandle);
```

As always, read the test application code for further "documentation"...
