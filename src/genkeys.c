#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <secp256k1.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>


#define KECCAK_ROUNDS 24
#define KECCAK_STATE_SIZE 25

static const unsigned int keccakf_rndc[24] = {
    0x00000001U, 0x00008082U, 0x0000808aU, 0x80008000U,
    0x0000808bU, 0x80000001U, 0x80008081U, 0x00008009U,
    0x0000008aU, 0x00000088U, 0x80008009U, 0x8000000aU,
    0x8000808bU, 0x0000008bU, 0x00008089U, 0x00008003U,
    0x00008002U, 0x00000080U, 0x0000800aU, 0x8000000aU,
    0x80008081U, 0x00008080U, 0x80000001U, 0x80008008U
};

static const int keccakf_rotc[24] = {
     1,  3,   6, 10, 15, 21,
    28, 36,  45, 55,  2, 14,
    27, 41,  56,  8, 25, 43,
    62, 18, 39, 61, 20, 44
};

static const int keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3,
    5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2,
    20, 14, 22,  9, 6,  1
};

static void keccakf(uint64_t st[25]) {
    int i, j, round;
    uint64_t t, bc[5];

    for (round = 0; round < KECCAK_ROUNDS; round++) {
      
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ((bc[(i + 1) % 5] << 1) | (bc[(i + 1) % 5] >> 63));
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

  
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = (t << keccakf_rotc[i]) | (t >> (64 - keccakf_rotc[i]));
            t = bc[0];
        }


        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

 
        st[0] ^= keccakf_rndc[round];
    }
}

static void keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen) {
    uint64_t st[25];
    uint8_t temp[200];
    int i, rsiz, rsizw;

    memset(st, 0, sizeof(st));

    rsiz = 200 - 2 * mdlen;
    rsizw = rsiz / 8;

    for (; inlen >= rsiz; inlen -= rsiz, in += rsiz) {
        for (i = 0; i < rsizw; i++)
            st[i] ^= ((uint64_t *)in)[i];
        keccakf(st);
    }

    memcpy(temp, in, inlen);
    temp[inlen++] = 1;
    memset(temp + inlen, 0, rsiz - inlen);
    temp[rsiz - 1] |= 0x80;

    for (i = 0; i < rsizw; i++)
        st[i] ^= ((uint64_t *)temp)[i];

    keccakf(st);

    memcpy(md, st, mdlen);
}

void keccak256(const uint8_t *in, int inlen, uint8_t *md) {
    keccak(in, inlen, md, 32);
}



void hex_encode(const unsigned char *data, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", data[i]);
    }
    out[len * 2] = '\0';
}

int main() {



    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

   
    unsigned char privkey[32];
    do {
        RAND_bytes(privkey, sizeof(privkey));
    } while (!secp256k1_ec_seckey_verify(ctx, privkey));


    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privkey)) {
        fprintf(stderr, "Error: failed to create public key.\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }

    unsigned char pubkey_serialized[65];
    size_t pubkey_len = 65;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkey_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);

 
    unsigned char hash[32];
    keccak256(pubkey_serialized + 1, 64, hash);

    unsigned char address[20];
    memcpy(address, hash + 12, 20);


    char priv_hex[65], pub_hex[129], addr_hex[43];
    hex_encode(privkey, 32, priv_hex);
    hex_encode(pubkey_serialized + 1, 64, pub_hex);

    strcpy(addr_hex, "0x");
    char tmp[41];
    hex_encode(address, 20, tmp);
    strncat(addr_hex, tmp, sizeof(addr_hex) - strlen(addr_hex) - 1);


    printf("Private Key: 0x%s\n", priv_hex);
    printf("Public Key: 0x%s\n", pub_hex);
    printf("Address: %s\n", addr_hex);


    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "Error: HOME environment variable not set.\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }

  
    char folderpath[512];
    snprintf(folderpath, sizeof(folderpath), "%s/.gorilla_wallets", home);

    mkdir(folderpath, 0777);


    char filepath[1024];
    int written = snprintf(filepath, sizeof(filepath), "%s/wallet.dat", folderpath);
    if (written < 0 || written >= (int)sizeof(filepath)) {
    fprintf(stderr, "Error: wallet path too long.\n");
    secp256k1_context_destroy(ctx);
    return 1;
    }


    FILE *f = fopen(filepath, "w");
    if (!f) {
        fprintf(stderr, "Error: could not open %s for writing.\n", filepath);
        secp256k1_context_destroy(ctx);
        return 1;
    }


    fprintf(f, "{\n");
    fprintf(f, "  \"address\": \"%s\",\n", addr_hex);
    fprintf(f, "  \"private_key\": \"0x%s\",\n", priv_hex);
    fprintf(f, "  \"public_key\": \"0x%s\"\n", pub_hex);
    fprintf(f, "}\n");

    fclose(f);

    printf("Wallet saved to: %s\n", filepath);

    secp256k1_context_destroy(ctx);
    return 0;
}
