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
#include <openssl/sha.h>

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

static int ensure_dir_mode(const char *path, mode_t mode) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        errno = ENOTDIR;
        return -1;
    }
    if (mkdir(path, mode) != 0 && errno != EEXIST) return -1;
    return 0;
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
    if (snprintf(dirpath, sizeof(dirpath), "%s/.gorilla_wallets", home) >= (int)sizeof(dirpath)) {
        fprintf(stderr, "Path too long\n");
        return EXIT_FAILURE;
    }

    if (ensure_dir_mode(dirpath, 0700) != 0) {
        perror("ensure_dir_mode");
        return EXIT_FAILURE;
    }

    char inpath[PATH_MAX];
    if (snprintf(inpath, sizeof(inpath), "%s/wallet.dat", dirpath) >= (int)sizeof(inpath)) {
        fprintf(stderr, "Input path too long\n");
        return EXIT_FAILURE;
    }

    struct stat st;
    if (stat(inpath, &st) != 0) {
        fprintf(stderr, "stat(%s) failed: %s\n", inpath, strerror(errno));
        return EXIT_FAILURE;
    }
    if (!S_ISREG(st.st_mode) || st.st_size < 0) {
        fprintf(stderr, "%s is not a valid regular file\n", inpath);
        return EXIT_FAILURE;
    }

    size_t plaintext_len = (size_t)st.st_size;
    FILE *inf = fopen(inpath, "rb");
    if (!inf) { perror("fopen"); return EXIT_FAILURE; }

    unsigned char *plaintext = malloc(plaintext_len ? plaintext_len : 1);
    if (!plaintext) { fclose(inf); fprintf(stderr, "malloc failed\n"); return EXIT_FAILURE; }

    if (fread(plaintext, 1, plaintext_len, inf) != plaintext_len) {
        fprintf(stderr, "Short read\n");
        fclose(inf);
        free(plaintext);
        return EXIT_FAILURE;
    }
    fclose(inf);


    unsigned char salt[SALT_SIZE], iv[IV_SIZE];
    if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        OPENSSL_cleanse(plaintext, plaintext_len);
        free(plaintext);
        return EXIT_FAILURE;
    }

    
    char pw1[512], pw2[512];
    if (!read_password("Enter password: ", pw1, sizeof(pw1)) ||
        !read_password("Confirm password: ", pw2, sizeof(pw2))) {
        fprintf(stderr, "Password input failed\n");
        free(plaintext);
        return EXIT_FAILURE;
    }

    if (strcmp(pw1, pw2) != 0) {
        fprintf(stderr, "Passwords do not match\n");
        OPENSSL_cleanse(pw1, sizeof(pw1));
        OPENSSL_cleanse(pw2, sizeof(pw2));
        free(plaintext);
        return EXIT_FAILURE;
    }
    OPENSSL_cleanse(pw2, sizeof(pw2)); 


    unsigned char key[KEY_SIZE];
    if (!PKCS5_PBKDF2_HMAC(pw1, strlen(pw1),
                           salt, sizeof(salt),
                           PBKDF2_ITER,
                           EVP_sha256(),
                           sizeof(key),
                           key)) {
        fprintf(stderr, "PBKDF2 failed\n");
        OPENSSL_cleanse(pw1, strlen(pw1));
        OPENSSL_cleanse(plaintext, plaintext_len);
        free(plaintext);
        return EXIT_FAILURE;
    }
    OPENSSL_cleanse(pw1, strlen(pw1));

   
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) print_ssl_error_and_exit("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        print_ssl_error_and_exit("EVP_EncryptInit_ex failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL) != 1)
        print_ssl_error_and_exit("Set IV length failed");

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        print_ssl_error_and_exit("EVP_EncryptInit_ex key/iv failed");

    unsigned char aad[MAGIC_LEN + SALT_SIZE];
    memcpy(aad, MAGIC, MAGIC_LEN);
    memcpy(aad + MAGIC_LEN, salt, SALT_SIZE);

    int len = 0;
    if (EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad)) != 1)
        print_ssl_error_and_exit("AAD failed");

    unsigned char *ciphertext = malloc(plaintext_len ? plaintext_len : 1);
    if (!ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(plaintext, plaintext_len);
        OPENSSL_cleanse(key, sizeof(key));
        free(plaintext);
        return EXIT_FAILURE;
    }

    int outlen = 0;
    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)plaintext_len) != 1)
            print_ssl_error_and_exit("EncryptUpdate failed");
    }

    int tmplen = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen) != 1)
        print_ssl_error_and_exit("EncryptFinal failed");

    int cipher_len = outlen + tmplen;
    unsigned char tag[TAG_SIZE];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1)
        print_ssl_error_and_exit("Get tag failed");

    EVP_CIPHER_CTX_free(ctx);

  
    char tmppath[PATH_MAX];
    if (snprintf(tmppath, sizeof(tmppath), "%s/wallet.dat.tmpXXXXXX", dirpath) >= (int)sizeof(tmppath)) {
        fprintf(stderr, "tmp path too long\n");
        goto cleanup;
    }

    int tmpfd = mkstemp(tmppath);
    if (tmpfd < 0) { perror("mkstemp"); goto cleanup; }
    if (fchmod(tmpfd, S_IRUSR | S_IWUSR) != 0) { perror("fchmod"); close(tmpfd); unlink(tmppath); goto cleanup; }

    if (write_all_fd(tmpfd, MAGIC, MAGIC_LEN) < 0 ||
        write_all_fd(tmpfd, salt, sizeof(salt)) < 0 ||
        write_all_fd(tmpfd, iv, sizeof(iv)) < 0 ||
        (cipher_len > 0 && write_all_fd(tmpfd, ciphertext, (size_t)cipher_len) < 0) ||
        write_all_fd(tmpfd, tag, sizeof(tag)) < 0) {
        perror("write tmp file");
        close(tmpfd);
        unlink(tmppath);
        goto cleanup;
    }

    if (fsync(tmpfd) != 0) { perror("fsync"); close(tmpfd); unlink(tmppath); goto cleanup; }
    if (close(tmpfd) != 0) { perror("close tmpfd"); unlink(tmppath); goto cleanup; }

    char outpath[PATH_MAX];
    if (snprintf(outpath, sizeof(outpath), "%s/wallet.dat", dirpath) >= (int)sizeof(outpath)) {
        fprintf(stderr, "out path too long\n");
        unlink(tmppath);
        goto cleanup;
    }

    if (rename(tmppath, outpath) != 0) {
        perror("rename");
        unlink(tmppath);
        goto cleanup;
    }

    printf("Wallet encrypted to: %s\n", outpath);

cleanup:
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(plaintext, plaintext_len);
    OPENSSL_cleanse(ciphertext, cipher_len ? (size_t)cipher_len : 1);
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(iv, sizeof(iv));
    OPENSSL_cleanse(tag, sizeof(tag));

    free(plaintext);
    free(ciphertext);

    EVP_cleanup();
    ERR_free_strings();

    return EXIT_SUCCESS;
}
