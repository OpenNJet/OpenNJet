#!/bin/bash

set -ex

mkdir bld
cd bld
sudo cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local
sudo cmake --build . --config Release  --target install
sudo apt-get -f -y install linux-tools-common linux-gcp linux-tools-$(uname -r)

echo $LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/usr/local/lib

sudo install /usr/local/lib/mariadb/libmariadb.so /usr/lib
sudo install -d /usr/lib/mariadb
sudo install -d /usr/lib/mariadb/plugin


sudo apt install libmysqlclient-dev
