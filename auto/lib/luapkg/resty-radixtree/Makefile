LUA_VERSION =       5.1
TARGET =            librestyradixtree.so 
PREFIX =            /usr/local
CFLAGS =            -O2 -g -Wall -fpic -std=c99 -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast 
LRADIX_LDFLAGS =     -shared
LUA_INCLUDE_DIR ?=   $(PREFIX)/include/lua5.1 
LUA_CMODULE_DIR ?=   $(PREFIX)/lib/lua/$(LUA_VERSION)
LUA_MODULE_DIR ?=    $(PREFIX)/share/lua/$(LUA_VERSION)
LUA_BIN_DIR ?=       $(PREFIX)/bin

DATAPERM =          644
EXECPERM =          755
BUILD_CFLAGS =      -I$(LUA_INCLUDE_DIR) 
OBJS =              src/rax.o src/easy_rax.o 

.PHONY: all clean install

.c.o:
	$(CC) -c $(CFLAGS) $(BUILD_CFLAGS) -o $@ $<

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(LRADIX_LDFLAGS) -o $@ $(OBJS)

install: $(TARGET)
	mkdir -p $(DESTDIR)$(LUA_CMODULE_DIR)
	rm -f $(DESTDIR)$(LUA_CMODULE_DIR)/$(TARGET)
	cp $(TARGET) $(DESTDIR)$(LUA_CMODULE_DIR)
	chmod $(EXECPERM) $(DESTDIR)$(LUA_CMODULE_DIR)/$(TARGET)

clean:
	rm -f src/*.o *.o $(TARGET)
