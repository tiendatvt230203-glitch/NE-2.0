CC     = gcc
CLANG  = clang

CFLAGS = -D_GNU_SOURCE -I. -Iinc -Iinc/core -Iinc/crypto -Iinc/db -I./include -Isrc/crypto/pqc/include -Wall -O2 -mcmodel=medium $(shell pg_config --includedir 2>/dev/null | xargs -I{} echo -I{})
LDFLAGS = -Wl,-rpath,'$$ORIGIN/lib' -lbpf -lelf -lz -lpthread \
          ./lib/libxdp.so.1.6.0 ./lib/libssl.so.3 ./lib/libcrypto.so.3 ./lib/libpq.so.5.14 ./lib/libscrypt.so

BPF_CFLAGS     = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

LIB_DIR = lib
TARGET  = network-encryptor

OPT_SRCS = $(wildcard src/crypto/options/common/*.c)

PQC_SRCS = $(wildcard src/crypto/pqc/*.c)

CORE_SRCS = $(wildcard src/core/forwarder/*.c) \
            $(wildcard src/core/dataplane/*.c) \
            $(wildcard src/core/iface/*.c) \
            $(wildcard src/core/flow/*.c) \
            $(wildcard src/core/failover/*.c) \
            $(wildcard src/core/util/*.c)

CRYPTO_COMMON_SRCS = $(wildcard src/crypto/common/*.c)

APP_SRC = main.c \
          $(CORE_SRCS) \
          $(CRYPTO_COMMON_SRCS) \
          $(OPT_SRCS) \
          $(PQC_SRCS)
APP_OBJ = $(APP_SRC:.c=.o)

DB_SRC = src/db/config.c \
         src/db/db_config.c \
         src/db/db_env.c \
         src/db/db_runtime.c \
         src/db/vault.c
DB_OBJ = $(DB_SRC:.c=.o)

BPF_OBJ = $(LIB_DIR)/lan.o \
          $(LIB_DIR)/wan.o

.PHONY: all clean dirs test

TEST_BINS = tests/test_bond_reorder.bin

all: dirs $(BPF_OBJ) $(TARGET)

test: $(TEST_BINS)
	./tests/test_bond_reorder.bin

tests/test_bond_reorder.bin: tests/test_bond_reorder.c src/core/dataplane/udp_reorder.c
	$(CC) $(CFLAGS) -Wextra -Werror $^ -lpthread -o $@

$(TARGET): $(APP_OBJ) $(DB_OBJ)
	$(CC) -o $@ $(APP_OBJ) $(DB_OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_DIR)/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -I./include -c $< -o $@

clean:
	rm -rf network-encryptor src/*.o src/core/*/*.o src/crypto/common/*.o \
		src/crypto/options/*.o src/crypto/options/common/*.o \
		src/crypto/pqc/*.o src/db/*.o *.o $(BPF_OBJ)
	rm -f $(TEST_BINS)
