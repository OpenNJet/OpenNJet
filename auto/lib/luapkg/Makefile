LUA_INCLUDE_DIR ?= $(LUAJIT_INC)
LUA_LIB_DIR ?= $(LUAJIT_LIB)
LUAINC_linux ?= $(LUAJIT_INC)

SUBDIRS = resty-cjson resty-http resty-balancer luasocket lsqlite3 resty-radixtree

MYMAKEFLAGS = 'LUA_INCLUDE_DIR=$(LUA_INCLUDE_DIR)' 'LUA_LIB_DIR=$(LUA_LIB_DIR)' 'LUAINC_linux=$(LUAINC_linux)'

all: 
	@for i in $(SUBDIRS); do \
	echo "make all in $$i..."; \
	(cd $$i; $(MAKE) $(MFLAGS) $(MYMAKEFLAGS) all); done
install:
	@for i in $(SUBDIRS); do \
        echo "make install in $$i..."; \
	(cd $$i; $(MAKE) install); done

clean:
	@for i in $(SUBDIRS); do \
        echo "make clean in $$i..."; \
	(cd $$i; $(MAKE) clean); done
