# Makefile for Gorilla Keys 🔑

CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto -lsecp256k1
SRC_DIR = src
BUILD_DIR = bin

# List of programs
PROGS = genkeys encryptwallet decryptwallet removewallet

all: $(PROGS)

# Build each program
genkeys:
	$(CC) $(CFLAGS) $(SRC_DIR)/genkeys.c -o $(BUILD_DIR)/genkeys $(LDFLAGS)

encryptwallet:
	$(CC) $(CFLAGS) $(SRC_DIR)/encryptwallet.c -o $(BUILD_DIR)/encryptwallet $(LDFLAGS)

decryptwallet:
	$(CC) $(CFLAGS) $(SRC_DIR)/decryptwallet.c -o $(BUILD_DIR)/decryptwallet $(LDFLAGS)

removewallet:
	$(CC) $(CFLAGS) $(SRC_DIR)/removewallet.c -o $(BUILD_DIR)/removewallet $(LDFLAGS)

.PHONY: clean all

clean:
	rm -rf $(BUILD_DIR)/*
