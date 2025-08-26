#define _POSIX_C_SOURCE 200809L

#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define SALT_SIZE 16
#define IV_SIZE 12  
#define TAG_SIZE 16
#define KEY_SIZE 32
#define PBKDF2_ITER 100000

#define MAGIC "GWL1"
#define MAGIC_LEN 4

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

static void print_ssl_error_and_exit(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
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

int main(void) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "Error: HOME environment variable not set.\n");
        return EXIT_FAILURE;
    }

    char dirpath[PATH_MAX];
    int ret = snprintf(dirpath, sizeof(dirpath), "%s/.gorilla_wallets", home);
    if (ret < 0 || ret >= (int)sizeof(dirpath)) return EXIT_FAILURE;

    char filepath[PATH_MAX];
    ret = snprintf(filepath, sizeof(filepath), "%s/wallet.dat", dirpath);
    if (ret < 0 || ret >= (int)sizeof(filepath)) return EXIT_FAILURE;

    struct stat st;
    if (stat(filepath, &st) != 0) {
        fprintf(stderr, "stat(%s) failed: %s\n", filepath, strerror(errno));
        return EXIT_FAILURE;
    }
    if (!S_ISREG(st.st_mode)) return EXIT_FAILURE;
    if (st.st_size < (MAGIC_LEN + SALT_SIZE + IV_SIZE + TAG_SIZE)) return EXIT_FAILURE;

    size_t filelen = (size_t)st.st_size;
    unsigned char *filebuf = malloc(filelen);
    if (!filebuf) return EXIT_FAILURE;

    FILE *f = fopen(filepath, "rb");
    if (!f) { free(filebuf); return EXIT_FAILURE; }
    size_t r = fread(filebuf, 1, filelen, f);
    fclose(f);
    if (r != filelen) { OPENSSL_cleanse(filebuf, filelen); free(filebuf); return EXIT_FAILURE; }

    if (memcmp(filebuf, MAGIC, MAGIC_LEN) != 0) { OPENSSL_cleanse(filebuf, filelen); free(filebuf); return EXIT_FAILURE; }

    unsigned char salt[SALT_SIZE];
    memcpy(salt, filebuf + MAGIC_LEN, SALT_SIZE);

    unsigned char iv[IV_SIZE];
    memcpy(iv, filebuf + MAGIC_LEN + SALT_SIZE, IV_SIZE);

    size_t header_len = MAGIC_LEN + SALT_SIZE + IV_SIZE;
    size_t cipherlen = filelen - header_len - TAG_SIZE;
    unsigned char *ciphertext = filebuf + header_len;
    unsigned char tag[TAG_SIZE];
    memcpy(tag, filebuf + header_len + cipherlen, TAG_SIZE);

    char pw[512];
    if (!read_password("Enter password: ", pw, sizeof(pw))) { OPENSSL_cleanse(filebuf, filelen); free(filebuf); return EXIT_FAILURE; }

    unsigned char key[KEY_SIZE];
    if (PKCS5_PBKDF2_HMAC(pw, strlen(pw), salt, SALT_SIZE, PBKDF2_ITER, EVP_sha256(), KEY_SIZE, key) != 1) {
        OPENSSL_cleanse(pw, strlen(pw));
        OPENSSL_cleanse(filebuf, filelen);
        free(filebuf);
        return EXIT_FAILURE;
    }
    OPENSSL_cleanse(pw, strlen(pw));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) print_ssl_error_and_exit("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) print_ssl_error_and_exit("EVP_DecryptInit_ex failed (init)");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1) print_ssl_error_and_exit("Failed to set IV length");
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) print_ssl_error_and_exit("EVP_DecryptInit_ex failed (key/iv)");

    unsigned char aad[MAGIC_LEN + SALT_SIZE];
    memcpy(aad, MAGIC, MAGIC_LEN);
    memcpy(aad + MAGIC_LEN, salt, SALT_SIZE);
    int tmplen = 0;
    if (EVP_DecryptUpdate(ctx, NULL, &tmplen, aad, sizeof(aad)) != 1) print_ssl_error_and_exit("EVP_DecryptUpdate (AAD) failed");

    unsigned char *plaintext = malloc(cipherlen ? cipherlen : 1);
    if (!plaintext) { EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, sizeof(key)); OPENSSL_cleanse(filebuf, filelen); free(filebuf); return EXIT_FAILURE; }

    int outlen = 0;
    if (cipherlen > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, (int)cipherlen) != 1) {
            EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, sizeof(key)); OPENSSL_cleanse(plaintext, cipherlen ? cipherlen : 1); OPENSSL_cleanse(filebuf, filelen); free(plaintext); free(filebuf); return EXIT_FAILURE;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1) print_ssl_error_and_exit("Failed to set GCM tag");

    int finlen = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext + outlen, &finlen) != 1) {
        EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, sizeof(key)); OPENSSL_cleanse(plaintext, cipherlen ? cipherlen : 1); OPENSSL_cleanse(filebuf, filelen); free(plaintext); free(filebuf); return EXIT_FAILURE;
    }

    int plainlen = outlen + finlen;
    EVP_CIPHER_CTX_free(ctx);

    char tmppath[PATH_MAX];
    ret = snprintf(tmppath, sizeof(tmppath), "%s/wallet.dat.tmpXXXXXX", dirpath);
    if (ret < 0 || ret >= (int)sizeof(tmppath)) goto cleanup;

    int tmpfd = mkstemp(tmppath);
    if (tmpfd < 0) goto cleanup;
    if (fchmod(tmpfd, S_IRUSR | S_IWUSR) != 0) { close(tmpfd); unlink(tmppath); goto cleanup; }
    if (write_all_fd(tmpfd, plaintext, plainlen) < 0) { close(tmpfd); unlink(tmppath); goto cleanup; }
    fsync(tmpfd);
    close(tmpfd);

    char outpath[PATH_MAX];
    ret = snprintf(outpath, sizeof(outpath), "%s/wallet.dat", dirpath);
    if (ret < 0 || ret >= (int)sizeof(outpath)) { unlink(tmppath); goto cleanup; }
    if (rename(tmppath, outpath) != 0) { unlink(tmppath); goto cleanup; }

    printf("Wallet decrypted successfully: %s\n", outpath);

cleanup:
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(filebuf, filelen ? filelen : 1);
    OPENSSL_cleanse(plaintext, cipherlen ? cipherlen : 1);
    free(filebuf);
    free(plaintext);

    EVP_cleanup();
    ERR_free_strings();

    return EXIT_SUCCESS;
}
