#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int main() {
    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "HOME not set.\n");
        return 1;
    }

    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/.gorilla_wallets/wallet.dat", home);

    
    struct stat st;
    if (stat(filepath, &st) != 0) {
        perror("Wallet file not found");
        return 1;
    }

   
    FILE *f = fopen(filepath, "r+b");
    if (!f) {
        perror("Failed to open wallet file");
        return 1;
    }

    unsigned char *zeros = calloc(1, st.st_size);
    if (!zeros) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(f);
        return 1;
    }

    fwrite(zeros, 1, st.st_size, f);
    fflush(f);
    fclose(f);
    free(zeros);

    
    if (unlink(filepath) == 0) {
        printf("Wallet securely deleted: %s\n", filepath);
    } else {
        perror("Error deleting wallet");
        return 1;
    }

    return 0;
}
