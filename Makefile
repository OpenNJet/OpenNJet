
default:	build

clean:
	rm -rf Makefile objs

.PHONY:	default clean

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/usr/local/njet/sbin/njet -t

	kill -USR2 `cat /usr/local/njet/logs/njet.pid`
	sleep 1
	test -f /usr/local/njet/logs/njet.pid.oldbin

	kill -QUIT `cat /usr/local/njet/logs/njet.pid.oldbin`

.PHONY:	build install modules upgrade
