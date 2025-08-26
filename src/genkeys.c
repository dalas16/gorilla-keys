
#define _POSIX_C_SOURCE 200809L
#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include <secp256k1.h>

// this new script has a simpler encryption mechanism before generation.You can add an extra layer of encryption via encryptwallet.c.
#define SALT_SIZE 16
#define IV_SIZE 12
#define TAG_SIZE 16
#define KEY_SIZE 32
#define PBKDF2_ITER 100000

#define MAGIC "GWL1"
#define MAGIC_LEN 4


static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x000000000000008bULL, 0x0000000000008089ULL, 0x0000000000008003ULL,
    0x0000000000008002ULL, 0x0000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
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


static inline uint64_t load64_le(const uint8_t *src) {
    uint64_t v;
    memcpy(&v, src, 8);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap64(v);
#endif
    return v;
}

static inline void store64_le(uint8_t *dst, uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap64(v);
#endif
    memcpy(dst, &v, 8);
}


static void keccakf(uint64_t st[25]) {
    int round, i, j;
    uint64_t bc[5], t;

    for (round = 0; round < 24; ++round) {
        for (i = 0; i < 5; ++i)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (i = 0; i < 5; ++i) {
            t = bc[(i + 4) % 5] ^ ((bc[(i + 1) % 5] << 1) | (bc[(i + 1) % 5] >> 63));
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        t = st[1];
        for (i = 0; i < 24; ++i) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = (t << keccakf_rotc[i]) | (t >> (64 - keccakf_rotc[i]));
            t = bc[0];
        }

        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; ++i)
                bc[i] = st[j + i];
            for (i = 0; i < 5; ++i)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        st[0] ^= keccakf_rndc[round];
    }
}


static void keccak(const uint8_t *in, size_t inlen, uint8_t *md, size_t mdlen) {
    uint64_t st[25];
    uint8_t temp[200];
    size_t i;
    size_t rsiz = 200 - 2 * mdlen;
    size_t rsizw = rsiz / 8;

    memset(st, 0, sizeof(st));


    while (inlen >= rsiz) {
        for (i = 0; i < rsizw; ++i) {
            uint64_t w = load64_le(in + i * 8);
            st[i] ^= w;
        }
        keccakf(st);
        inlen -= rsiz;
        in += rsiz;
    }


    memset(temp, 0, rsiz);
    if (inlen > 0) memcpy(temp, in, inlen);
    temp[inlen] = 0x01;
    temp[rsiz - 1] |= 0x80;

    for (i = 0; i < rsizw; ++i) {
        uint64_t w = load64_le(temp + i * 8);
        st[i] ^= w;
    }

    keccakf(st);

  
    for (i = 0; i < mdlen; i += 8) {
        size_t rem = mdlen - i;
        uint64_t w = st[i / 8];
        uint8_t buf[8];
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        uint64_t wbe = __builtin_bswap64(w);
        memcpy(buf, &wbe, 8);
#else
        memcpy(buf, &w, 8);
#endif
        memcpy(md + i, buf, rem < 8 ? rem : 8);
    }
}


static void keccak256(const uint8_t *in, size_t inlen, uint8_t *md) {
    keccak(in, inlen, md, 32);
}


static void hex_encode(const uint8_t *data, size_t len, char *out) {
    static const char hexchars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[i * 2]     = hexchars[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = hexchars[data[i] & 0xF];
    }
    out[len * 2] = '\0';
}


static ssize_t write_all_fd(int fd, const void *buf, size_t count) {
    const unsigned char *p = buf;
    size_t left = count;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        left -= (size_t)w;
        p += w;
    }
    return (ssize_t)count;
}

static void print_ssl_errors(const char *pref) {
    fprintf(stderr, "%s\n", pref);
    ERR_print_errors_fp(stderr);
}

char *read_password(const char *prompt, char *buf, size_t buflen) {
    struct termios oldt, newt;
    printf("%s", prompt);
    fflush(stdout);

    if (tcgetattr(STDIN_FILENO, &oldt) != 0)
        return NULL;
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0)
        return NULL;

    if (fgets(buf, buflen, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        return NULL;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    buf[strcspn(buf, "\n")] = '\0';
    printf("\n");
    return buf;
}

int main(void) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

  
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        fprintf(stderr, "Failed to create secp256k1 context\n");
        return EXIT_FAILURE;
    }


    unsigned char privkey[32];
    int ok = 0;
    for (int attempts = 0; attempts < 1000 && !ok; ++attempts) {
        if (RAND_bytes(privkey, sizeof(privkey)) != 1) {
            print_ssl_errors("RAND_bytes failed");
            secp256k1_context_destroy(ctx);
            return EXIT_FAILURE;
        }
        ok = secp256k1_ec_seckey_verify(ctx, privkey);
    }
    if (!ok) {
        fprintf(stderr, "Failed to generate a valid secp256k1 secret key\n");
        secp256k1_context_destroy(ctx);
        return EXIT_FAILURE;
    }

   
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privkey)) {
        fprintf(stderr, "secp256k1_ec_pubkey_create failed\n");
        secp256k1_context_destroy(ctx);
        OPENSSL_cleanse(privkey, sizeof(privkey));
        return EXIT_FAILURE;
    }

  
    unsigned char pubser[65];
    size_t pubserlen = sizeof(pubser);
    if (!secp256k1_ec_pubkey_serialize(ctx, pubser, &pubserlen, &pubkey, SECP256K1_EC_UNCOMPRESSED) || pubserlen != 65) {
        fprintf(stderr, "pubkey serialize failed\n");
        secp256k1_context_destroy(ctx);
        OPENSSL_cleanse(privkey, sizeof(privkey));
        return EXIT_FAILURE;
    }


    unsigned char hash[32];
    keccak256(pubser + 1, 64, hash);

    unsigned char address[20];
    memcpy(address, hash + 12, 20); 


    char addr_hex[2 + 40 + 1];
    addr_hex[0] = '0';
    addr_hex[1] = 'x';
    hex_encode(address, 20, addr_hex + 2);

    char pub_hex[2 * 64 + 1];
    hex_encode(pubser + 1, 64, pub_hex);

    char priv_hex[2 * 32 + 1];
    hex_encode(privkey, 32, priv_hex);

    size_t json_needed = 256 + strlen(addr_hex) + strlen(pub_hex) + strlen(priv_hex);
    char *json = malloc(json_needed);
    if (!json) {
        fprintf(stderr, "malloc failed\n");
        secp256k1_context_destroy(ctx);
        OPENSSL_cleanse(privkey, sizeof(privkey));
        return EXIT_FAILURE;
    }
    int json_len = snprintf(json, json_needed,
        "{\n"
        "  \"address\": \"%s\",\n"
        "  \"private_key\": \"0x%s\",\n"
        "  \"public_key\": \"0x%s\"\n"
        "}\n",
        addr_hex, priv_hex, pub_hex);
    if (json_len < 0 || (size_t)json_len >= json_needed) {
        fprintf(stderr, "JSON snprintf failed\n");
        free(json);
        secp256k1_context_destroy(ctx);
        OPENSSL_cleanse(privkey, sizeof(privkey));
        return EXIT_FAILURE;
    }

 
    printf("Address: %s\n", addr_hex);
    fprintf(stderr, "Your private key will be saved ENCRYPTED to disk. Do NOT share your password.\n");


    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "HOME not set\n");
        free(json);
        secp256k1_context_destroy(ctx);
        OPENSSL_cleanse(privkey, sizeof(privkey));
        return EXIT_FAILURE;
    }

    char dirpath[PATH_MAX];
    if (snprintf(dirpath, sizeof(dirpath), "%s/.gorilla_wallets", home) >= (int)sizeof(dirpath)) {
        fprintf(stderr, "Path too long\n");
        free(json);
        secp256k1_context_destroy(ctx);
        OPENSSL_cleanse(privkey, sizeof(privkey));
        return EXIT_FAILURE;
    }
    if (mkdir(dirpath, 0700) != 0 && errno != EEXIST) {
        perror("mkdir");
        free(json);
        secp256k1_context_destroy(ctx);
        OPENSSL_cleanse(privkey, sizeof(privkey));
        return EXIT_FAILURE;
    }


    printf("Save encrypted wallet to %s/wallet.dat ? [y/N]: ", dirpath);
    fflush(stdout);
    int c = getchar();
    while (c != EOF && c != '\n') {
        if (c != '\r') break;
        c = getchar();
    }
    if (!(c == 'y' || c == 'Y')) {
        printf("Aborted: wallet not saved.\n");
        free(json);
        secp256k1_context_destroy(ctx);
        OPENSSL_cleanse(privkey, sizeof(privkey));
        return EXIT_SUCCESS;
    }


    char pw1[512], pw2[512];
    if (!read_password("Enter password to encrypt wallet: ", pw1, sizeof(pw1))) {
        fprintf(stderr, "Password input failed\n");
        goto cleanup_all;
}
    if (!read_password("Confirm password: ", pw2, sizeof(pw2))) {
       fprintf(stderr, "Password input failed\n");
       goto cleanup_all;
}
    if (strcmp(pw1, pw2) != 0) {
       fprintf(stderr, "Passwords do not match\n");
       goto cleanup_all;
   }



    unsigned char salt[SALT_SIZE];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        print_ssl_errors("RAND_bytes(salt) failed");
        goto cleanup_all;
    }
    unsigned char key[KEY_SIZE];
    if (!PKCS5_PBKDF2_HMAC(pw1, strlen(pw1), salt, sizeof(salt), PBKDF2_ITER, EVP_sha256(), KEY_SIZE, key)) {
        print_ssl_errors("PBKDF2 failed");
        goto cleanup_all;
    }

    OPENSSL_cleanse(pw1, strlen(pw1));
    OPENSSL_cleanse(pw2, strlen(pw2));


    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        print_ssl_errors("RAND_bytes(iv) failed");
        OPENSSL_cleanse(key, sizeof(key));
        goto cleanup_all;
    }

    EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
    if (!ectx) { print_ssl_errors("EVP_CIPHER_CTX_new failed"); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }
    if (EVP_EncryptInit_ex(ectx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) { print_ssl_errors("EVP_EncryptInit_ex"); EVP_CIPHER_CTX_free(ectx); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }
    if (EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) { print_ssl_errors("Set IV len"); EVP_CIPHER_CTX_free(ectx); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }
    if (EVP_EncryptInit_ex(ectx, NULL, NULL, key, iv) != 1) { print_ssl_errors("EVP_EncryptInit_ex (key/iv)"); EVP_CIPHER_CTX_free(ectx); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }

   
    unsigned char aad[MAGIC_LEN + SALT_SIZE];
    memcpy(aad, MAGIC, MAGIC_LEN);
    memcpy(aad + MAGIC_LEN, salt, SALT_SIZE);
    int tmplen = 0;
    if (EVP_EncryptUpdate(ectx, NULL, &tmplen, aad, sizeof(aad)) != 1) { print_ssl_errors("EVP_EncryptUpdate(AAD)"); EVP_CIPHER_CTX_free(ectx); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }

    size_t plaintext_len = (size_t)json_len;
    unsigned char *ciphertext = malloc(plaintext_len ? plaintext_len : 1);
    if (!ciphertext) { fprintf(stderr, "malloc failed\n"); EVP_CIPHER_CTX_free(ectx); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }
    int outlen = 0;
    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ectx, ciphertext, &outlen, (unsigned char *)json, (int)plaintext_len) != 1) { print_ssl_errors("EVP_EncryptUpdate"); EVP_CIPHER_CTX_free(ectx); free(ciphertext); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }
    }
    int flen = 0;
    if (EVP_EncryptFinal_ex(ectx, ciphertext + outlen, &flen) != 1) { print_ssl_errors("EVP_EncryptFinal_ex"); EVP_CIPHER_CTX_free(ectx); free(ciphertext); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }
    int cipherlen = outlen + flen;

    unsigned char tag[TAG_SIZE];
    if (EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) { print_ssl_errors("Get tag failed"); EVP_CIPHER_CTX_free(ectx); free(ciphertext); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }
    EVP_CIPHER_CTX_free(ectx);

 
    char tmppath[PATH_MAX];
    if (snprintf(tmppath, sizeof(tmppath), "%s/wallet.dat.tmpXXXXXX", dirpath) >= (int)sizeof(tmppath)) {
        fprintf(stderr, "tmp path too long\n"); free(ciphertext); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all;
    }
    int tmpfd = mkstemp(tmppath);
    if (tmpfd < 0) { perror("mkstemp"); free(ciphertext); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }
    if (fchmod(tmpfd, S_IRUSR | S_IWUSR) != 0) { perror("fchmod"); close(tmpfd); unlink(tmppath); free(ciphertext); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }


    if (write_all_fd(tmpfd, MAGIC, MAGIC_LEN) < 0 ||
        write_all_fd(tmpfd, salt, sizeof(salt)) < 0 ||
        write_all_fd(tmpfd, iv, sizeof(iv)) < 0 ||
        (cipherlen > 0 && write_all_fd(tmpfd, ciphertext, (size_t)cipherlen) < 0) ||
        write_all_fd(tmpfd, tag, sizeof(tag)) < 0) {
        perror("write");
        close(tmpfd);
        unlink(tmppath);
        free(ciphertext);
        OPENSSL_cleanse(key, sizeof(key));
        goto cleanup_all;
    }

    if (fsync(tmpfd) != 0) { perror("fsync"); close(tmpfd); unlink(tmppath); free(ciphertext); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }
    if (close(tmpfd) != 0) { perror("close tmp"); unlink(tmppath); free(ciphertext); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }

    char outpath[PATH_MAX];
    if (snprintf(outpath, sizeof(outpath), "%s/wallet.dat", dirpath) >= (int)sizeof(outpath)) { fprintf(stderr, "out path too long\n"); unlink(tmppath); free(ciphertext); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }
    if (rename(tmppath, outpath) != 0) { perror("rename"); unlink(tmppath); free(ciphertext); OPENSSL_cleanse(key, sizeof(key)); goto cleanup_all; }

    printf("Encrypted wallet saved to: %s\n", outpath);

 
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(privkey, sizeof(privkey));
    OPENSSL_cleanse(priv_hex, sizeof(priv_hex));
    OPENSSL_cleanse(pub_hex, sizeof(pub_hex));
    OPENSSL_cleanse(json, json_len ? (size_t)json_len : 1);

    free(json);
    free(ciphertext);
    secp256k1_context_destroy(ctx);
    EVP_cleanup();
    ERR_free_strings();
    return EXIT_SUCCESS;

cleanup_all:
    OPENSSL_cleanse(privkey, sizeof(privkey));
    OPENSSL_cleanse(priv_hex, sizeof(priv_hex));
    OPENSSL_cleanse(pub_hex, sizeof(pub_hex));
    OPENSSL_cleanse(json, json_len ? (size_t)json_len : 1);
    free(json);
    secp256k1_context_destroy(ctx);
    EVP_cleanup();
    ERR_free_strings();
    return EXIT_FAILURE;
}
