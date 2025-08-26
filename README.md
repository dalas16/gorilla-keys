# Gorilla Wallet 🔑

A lightweight C toolset for Ethereum-compatible secp256k1 key management.

## Notes

- 
## Features

- `genkeys` — Generates a valid secp256k1 private key, derives the uncompressed public key, computes the Ethereum-style address (Keccak-256), and saves the wallet to `~/.gorilla_wallets/wallet.dat`.
- `encryptwallet` — Encrypts the wallet file using AES-256 with password protection.
- `decryptwallet` — Decrypts the wallet file back to JSON.
- `removewallet` — Deletes the wallet from local storage.
- `sign` - Signs a transaction by using your private key (accepts chainid) + gives a raw tx ready for broadcast via your node

## Dependencies

- GCC or Clang
- OpenSSL (`libssl-dev`)
- libsecp256k1 (`libsecp256k1-dev`)

## Build

```bash
# Create build folder
mkdir -p bin

# Build all tools
make
