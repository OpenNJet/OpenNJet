LUA_VERSION =       5.1
TARGET =            lsqlite3complete.so
PREFIX =            /usr/local
CFLAGS =            -O2  -I ../../sqlite3
LSQLITE3_CFLAGS =   -fpic -DLSQLITE_VERSION='"0.9.6"' -Dluaopen_lsqlite3=luaopen_lsqlite3complete
LSQLITE3_LDFLAGS =  -shared
LUA_INCLUDE_DIR ?=   $(PREFIX)/include/lua5.1 
LUA_CMODULE_DIR ?=   $(PREFIX)/lib/lua/$(LUA_VERSION)
LUA_MODULE_DIR ?=    $(PREFIX)/share/lua/$(LUA_VERSION)
LUA_BIN_DIR ?=       $(PREFIX)/bin
LDFLAGS =            ../../sqlite3/libsqlite3.a

DATAPERM =          644
EXECPERM =          755
BUILD_CFLAGS =      -I$(LUA_INCLUDE_DIR) $(LSQLITE3_CFLAGS)
#OBJS =              sqlite3.o lsqlite3.o
OBJS =              lsqlite3.o

.PHONY: all clean install

.c.o:
	$(CC) -c $(CFLAGS) $(BUILD_CFLAGS) -o $@ $<

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $(LSQLITE3_LDFLAGS) -o $@ $(OBJS) $(LDFLAGS)

install: $(TARGET)
	mkdir -p $(DESTDIR)$(LUA_CMODULE_DIR)
	rm -f $(DESTDIR)$(LUA_CMODULE_DIR)/$(TARGET)
	cp $(TARGET) $(DESTDIR)$(LUA_CMODULE_DIR)
	chmod $(EXECPERM) $(DESTDIR)$(LUA_CMODULE_DIR)/$(TARGET)

clean:
	rm -f *.o $(TARGET)

