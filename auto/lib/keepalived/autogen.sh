#!/bin/sh

mkdir -p build-aux

aclocal --install -I m4
autoheader
automake --add-missing
autoreconf -B /usr/local/lib -I /usr/local/include
