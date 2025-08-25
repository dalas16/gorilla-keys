# Gorilla Keys 🔑

A lightweight C tool to generate secp256k1 Ethereum-compatible keypairs and save them in a simple JSON wallet file.

## Features
- Generates a valid secp256k1 private key
- Derives the uncompressed public key
- Computes the Ethereum-style address (Keccak-256)
- Saves wallet to `~/.gorilla_wallets/wallet.dat`

## Build

Dependencies:
- GCC or Clang
- OpenSSL (`libssl-dev`)
- libsecp256k1 (`libsecp256k1-dev`)

```bash
make
