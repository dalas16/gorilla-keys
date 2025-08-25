#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#define SALT_SIZE 16
#define IV_SIZE 16
#define HMAC_SIZE 32
#define KEY_SIZE 32
#define PBKDF2_ITER 100000

int main() {
    const char *wallet_path = "/home/dallas-user/.gorilla_wallets/wallet.dat";


    FILE *f = fopen(wallet_path, "rb");
    if (!f) { perror("Open wallet.dat"); return 1; }

    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (filesize < SALT_SIZE + IV_SIZE + HMAC_SIZE) {
        fprintf(stderr, "Invalid wallet file\n");
        fclose(f);
        return 1;
    }

    unsigned char *filebuf = malloc(filesize);
    fread(filebuf, 1, filesize, f);
    fclose(f);

    unsigned char salt[SALT_SIZE], iv[IV_SIZE], hmac_stored[HMAC_SIZE];
    memcpy(salt, filebuf, SALT_SIZE);
    memcpy(iv, filebuf + SALT_SIZE, IV_SIZE);
    memcpy(hmac_stored, filebuf + filesize - HMAC_SIZE, HMAC_SIZE);
    unsigned char *ciphertext = filebuf + SALT_SIZE + IV_SIZE;
    int cipherlen = filesize - SALT_SIZE - IV_SIZE - HMAC_SIZE;


    char password[128];
    printf("Enter password: ");
    scanf("%127s", password);


    unsigned char key[KEY_SIZE];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, PBKDF2_ITER, EVP_sha256(), KEY_SIZE, key)) {
        fprintf(stderr, "Key derivation failed\n");
        free(filebuf);
        return 1;
    }

    
    unsigned char hmac_calc[HMAC_SIZE];
    HMAC(EVP_sha256(), key, KEY_SIZE, ciphertext, cipherlen, hmac_calc, NULL);

    if (memcmp(hmac_calc, hmac_stored, HMAC_SIZE) != 0) {
        fprintf(stderr, "HMAC verification failed: wrong password or corrupted file\n");
        free(filebuf);
        return 1;
    }

 
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char *plaintext = malloc(cipherlen + 16);
    int outlen1, outlen2;
    EVP_DecryptUpdate(ctx, plaintext, &outlen1, ciphertext, cipherlen);
    if (!EVP_DecryptFinal_ex(ctx, plaintext + outlen1, &outlen2)) {
        fprintf(stderr, "Decryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(filebuf);
        free(plaintext);
        return 1;
    }
    EVP_CIPHER_CTX_free(ctx);

    int plainlen = outlen1 + outlen2;


    FILE *out = fopen(wallet_path, "wb");
    if (!out) { perror("Write wallet.dat"); free(filebuf); free(plaintext); return 1; }
    fwrite(plaintext, 1, plainlen, out);
    fclose(out);

    printf("Wallet decrypted successfully: %s\n", wallet_path);

    free(filebuf);
    free(plaintext);
    return 0;
}
