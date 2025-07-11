CC =	/usr/bin/cc
# for debug
# CFLAGS =  -pipe  -O -W -Wall -Wpointer-arith -Wno-unused-parameter -Werror -g -O0 -ggdb -fno-omit-frame-pointer -Wno-implicit-fallthrough -fPIC -DNDK_SET_VAR
CFLAGS = -pipe  -O -W -Wall -Wpointer-arith -Wno-unused-parameter -Werror -g -O2 -g -Wno-implicit-fallthrough -fPIC -DNDK_SET_VAR
CPP =	/usr/bin/cc -E
LINK =	$(CC)
LDFLAGS =  ../../auto/lib/tongsuo/.openssl/lib/libssl.a \
           ../../auto/lib/tongsuo/.openssl/lib/libcrypto.a \
           ../../auto/lib/sqlite3/libsqlite3.a \
	   -lpthread -ldl -lm

ALL_INCS = -I ../../src/core \
    -I ../../auto/lib/tongsuo/.openssl/include \
	-I ../../auto/lib/sqlite3

BIN_DIR := ../bin
OPENSSL_DIR = $(CURDIR)/../../auto/lib/tongsuo/.openssl
SRC := src/main.c src/utils.c

TARGET = $(BIN_DIR)/agw_passwd 

build: $(TARGET)


../../auto/lib/tongsuo/.openssl/lib/libssl.a:
	cd ../../auto/lib/tongsuo \
	&& if [ ! -f Makefile ]; then ./config  no-tests --prefix=$(OPENSSL_DIR)   no-shared   no-threads --strict-warnings enable-ntls ; fi \
	&& make \
	&& make install_sw LIBDIR=lib


../../auto/lib/sqlite3/libsqlite3.a:
	cd ../../auto/lib/sqlite3  && \
	   ./configure --disable-shared --enable-static && \
	   make

# ../../modules/njet-openapi-parser-module/src/sqlite3/sqlite3.c
$(TARGET): agw_passwd.c  ../../auto/lib/sqlite3/libsqlite3.a ../../auto/lib/tongsuo/.openssl/lib/libssl.a
	$(CC) $(CFLAGS) $(ALL_INCS) -o $@ $^ $(LDFLAGS) 

clean:
	rm -f $(TARGET)
