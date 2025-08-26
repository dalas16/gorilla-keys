# Makefile for Gorilla Keys 🔑

CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto
SECP_FLAGS = -lsecp256k1
SRC_DIR = src
BUILD_DIR = bin


PROGS = genkeys encryptwallet decryptwallet removewallet

all: $(BUILD_DIR) $(PROGS)


$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)


%: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $(BUILD_DIR)/$@ $(LDFLAGS)


genkeys: $(SRC_DIR)/genkeys.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $(BUILD_DIR)/$@ $(LDFLAGS) $(SECP_FLAGS)

.PHONY: clean all

clean:
	rm -rf $(BUILD_DIR)/*