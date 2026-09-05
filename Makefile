CC     = gcc
CLANG  = clang

CFLAGS = -D_GNU_SOURCE -I. -Iinc -Iinc/core -Iinc/crypto -I./include -Isrc/crypto/pqc/include -Wall -Wextra -O2 -mcmodel=medium
# The packaged libxdp contains the matching libbpf implementation.  Do not
# also link the appliance's libbpf.so.0 (0.5.x): mixing both ABIs makes BPF
# objects created by one implementation crash when used by the other.
LDFLAGS = -Wl,-rpath,'$$ORIGIN/lib' -lelf -lz -lpthread \
          ./lib/libxdp.so.1.6.0 ./lib/libscrypt.so

BPF_CFLAGS     = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

LIB_DIR = lib
TARGET  = network-encryptor

APP_SRC = main.c \
          src/core/forwarder/forwarder.c \
          src/core/dataplane/crypto_route.c \
          src/core/dataplane/idle.c src/core/dataplane/local_egress.c \
          src/core/dataplane/packet_util.c \
          src/core/dataplane/wan_ingress.c src/core/iface/xdp_attach.c \
          src/core/iface/xdp_interface.c \
          src/core/util/static_config.c src/core/util/cpu_map.c \
          src/crypto/common/eth_parse.c \
          src/crypto/common/packet_crypto.c src/crypto/pqc/pqc_l2_option.c \
          src/crypto/pqc/traffic_crypto.c
APP_OBJ = $(APP_SRC:.c=.o)

BPF_OBJ = $(LIB_DIR)/lan.o \
          $(LIB_DIR)/wan.o

.PHONY: all clean dirs

all: dirs $(BPF_OBJ) $(TARGET)

$(TARGET): $(APP_OBJ)
	$(CC) -o $@ $(APP_OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_DIR)/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -I./include -c $< -o $@


clean:
	rm -rf network-encryptor src/*.o src/core/*/*.o src/crypto/common/*.o \
		src/crypto/options/*.o src/crypto/options/common/*.o \
		src/crypto/pqc/*.o *.o $(BPF_OBJ)
