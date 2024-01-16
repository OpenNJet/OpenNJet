#!/usr/bin/env bash


. /etc/os-release

ARCH=$(dpkg --print-architecture)

NJT_VERSION=`grep "define NJT_VERSION" ../src/core/njet.h |awk '{print $3}' |sed 's/"//g'`

sed -e "s/{{NJT_VERSION}}/$NJT_VERSION/g" -e "s/{{ARCH}}/$ARCH/g" < deb_control.tmpl > deb/DEBIAN/control 
chmod 755 deb/DEBIAN
chmod 555 deb/DEBIAN/*
chmod 644 deb/DEBIAN/control

dpkg -b deb njet_${NJT_VERSION}-1~ubuntu.${VERSION_ID}~${VERSION_CODENAME}_$ARCH.deb
