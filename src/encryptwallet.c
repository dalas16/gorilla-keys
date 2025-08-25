#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#define SALT_SIZE 16
#define IV_SIZE 16
#define HMAC_SIZE 32
#define KEY_SIZE 32
#define PBKDF2_ITER 100000

int main() {

    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "Error: HOME environment variable not set.\n");
        return 1;
    }

   
    char wallet_path[1024];
    snprintf(wallet_path, sizeof(wallet_path), "%s/.gorilla_wallets/wallet.dat", home);

    char out_path[1024];
    snprintf(out_path, sizeof(out_path), "%s/.gorilla_wallets/wallet.dat", home);

    
    FILE *f = fopen(wallet_path, "rb");
    if (!f) {
        fprintf(stderr, "Open wallet.dat: %s\n", strerror(errno));
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *plaintext = malloc(filesize);
    if (!plaintext) { fclose(f); fprintf(stderr, "Memory allocation failed\n"); return 1; }
    fread(plaintext, 1, filesize, f);
    fclose(f);

 
    unsigned char salt[SALT_SIZE], iv[IV_SIZE];
    if (!RAND_bytes(salt, SALT_SIZE) || !RAND_bytes(iv, IV_SIZE)) {
        fprintf(stderr, "Random generation failed\n");
        free(plaintext);
        return 1;
    }

 
    char password[128];
    printf("Enter password: ");
    if (scanf("%127s", password) != 1) {
        fprintf(stderr, "Password input failed\n");
        free(plaintext);
        return 1;
    }

    unsigned char key[KEY_SIZE];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, PBKDF2_ITER, EVP_sha256(), KEY_SIZE, key)) {
        fprintf(stderr, "Key derivation failed\n");
        free(plaintext);
        return 1;
    }

    /
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { fprintf(stderr, "EVP context allocation failed\n"); free(plaintext); return 1; }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return 1;
    }

    unsigned char *ciphertext = malloc(filesize + 16);
    if (!ciphertext) { EVP_CIPHER_CTX_free(ctx); free(plaintext); fprintf(stderr, "Memory allocation failed\n"); return 1; }

    int outlen1 = 0, outlen2 = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen1, plaintext, filesize) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext + outlen1, &outlen2) != 1) {
        fprintf(stderr, "Encryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        free(ciphertext);
        return 1;
    }
    EVP_CIPHER_CTX_free(ctx);

    int cipherlen = outlen1 + outlen2;


    unsigned char hmac[HMAC_SIZE];
    if (!HMAC(EVP_sha256(), key, KEY_SIZE, ciphertext, cipherlen, hmac, NULL)) {
        fprintf(stderr, "HMAC computation failed\n");
        free(plaintext);
        free(ciphertext);
        return 1;
    }


    FILE *out = fopen(out_path, "wb");
    if (!out) {
        fprintf(stderr, "Cannot open %s for writing: %s\n", out_path, strerror(errno));
        free(plaintext);
        free(ciphertext);
        return 1;
    }
    fwrite(salt, 1, SALT_SIZE, out);
    fwrite(iv, 1, IV_SIZE, out);
    fwrite(ciphertext, 1, cipherlen, out);
    fwrite(hmac, 1, HMAC_SIZE, out);
    fclose(out);

    printf("Wallet encrypted to: %s\n", out_path);

    free(plaintext);
    free(ciphertext);
    return 0;
}
