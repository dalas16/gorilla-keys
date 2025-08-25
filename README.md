# Gorilla Keys

A minimal C program that generates Ethereum-compatible secp256k1 keypairs and saves them.

## Build

Requires:
- OpenSSL
- libsecp256k1

```bash
gcc genkeys.c -o genkeys -lssl -lcrypto -lsecp256k1
or use Makefile provided