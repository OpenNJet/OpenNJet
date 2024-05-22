LUA_VERSION =       5.1

PREFIX ?=          /usr/local
LUA_INCLUDE_DIR ?= $(PREFIX)/include
LUA_LIB_DIR ?=     $(PREFIX)/lib/lua/$(LUA_VERSION)
LUA_CMODULE_DIR ?=   $(PREFIX)/lib/lua/$(LUA_VERSION)
LUA_MODULE_DIR ?=    $(PREFIX)/share/lua/$(LUA_VERSION)
INSTALL ?= install

.PHONY: all install

SRC := chash.c
OBJ := $(SRC:.c=.o)

C_SO_NAME := librestychash.so

CFLAGS := -O3 -g -Wall -fpic

LDFLAGS := -shared
# on Mac OS X, one should set instead:
# LDFLAGS := -bundle -undefined dynamic_lookup

ifeq ($(shell uname),Darwin)
	LDFLAGS := -bundle -undefined dynamic_lookup
	C_SO_NAME := librestychash.dylib
endif

MY_CFLAGS := $(CFLAGS) -DBUILDING_SO
MY_LDFLAGS := $(LDFLAGS) -fvisibility=hidden

.PHONY = all clean install

all : $(C_SO_NAME)

${OBJ} : %.o : %.c
	$(CC) $(MY_CFLAGS) -c $<

${C_SO_NAME} : ${OBJ}
	$(CC) $(MY_LDFLAGS) $^ -o $@

#export TEST_NGINX_NO_CLEAN=1

clean:; rm -f *.o *.so a.out *.d

install:
	$(INSTALL) -d $(DESTDIR)$(LUA_MODULE_DIR)/resty
	$(INSTALL) -d $(DESTDIR)$(LUA_MODULE_DIR)/resty/balancer
	$(INSTALL) lib/resty/*.lua $(DESTDIR)$(LUA_MODULE_DIR)/resty
	$(INSTALL) lib/resty/balancer/*.lua $(DESTDIR)$(LUA_MODULE_DIR)/resty/balancer
	$(INSTALL) $(C_SO_NAME) $(DESTDIR)$(LUA_CMODULE_DIR)/

