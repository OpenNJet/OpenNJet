#!/bin/bash
#tgtdir=/Users/`whoami`/njet
tgtdir=/etc/njet
tgbindir=/usr/sbin/njet
tglogdir=/var/log/njet/error.log
modulesdir=/usr/lib/njet/modules
git_tag=""
if [ $# -eq 2 ];
then
  git_tag="NJT_$2"
fi
export LUAJIT_INC="`pwd`/luajit/src"
export LUAJIT_LIB="`pwd`/luajit/src"
#--with-ld-opt='-Wl,-rpath,/usr/local/tassl/openssl/lib'
#--with-cc-opt=-I'auto/lib/tassl/include' --with-ld-opt='-Wl,-rpath,/usr/local/tassl/openssl/lib'
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-stream-proto-module"
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-stream-proxy-protocol-tlv-module"
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-util-module"  #njet-http-if-location-module
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-http-if-location-module"  #njet-http-if-location-module
NJET_MODULES="$NJET_MODULES --add-module=src/ext/lua/kit"
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-stream-upstream-dynamic-servers-module"
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-http-upstream-dynamic-servers-module"
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-http-match-module"
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-http-sticky-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-location-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-location-api-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-dyn-server-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-dyn-server-api-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-upstream-api-module"
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-mqconf-module"
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-vts-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-vtsc-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-vtsd-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-helper-ctrl-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-helper-broker-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-helper-ha-module"
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-http-kv-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-config-api-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-sendmsg-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-dyn-bwlist-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-dyn-map-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-split-clients-2-module"
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-http-proxy-connect-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-health-check-helper"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-doc-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-dyn-ssl-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-ssl-api-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-dyn-limit-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./src/ext/lua/http"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./src/ext/lua/stream"
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-gossip-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-app-sticky-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-cluster-limit-conn-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-cluster-limit-req-module"
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-cache-purge-module"
# NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-fault-inject-module"
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-http-fault-inject-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-dyn-fault-inject-module"
NJET_MODULES="$NJET_MODULES --add-module=./modules/njet-jwt-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-sysguard-cpu-module"
NJET_MODULES="$NJET_MODULES --add-dynamic-module=./modules/njet-http-register-module"
PATH_INFO=" --conf-path=/etc/njet/njet.conf   --prefix=$tgtdir --sbin-path=$tgbindir --modules-path=$modulesdir "
LIB_SRC_PATH=" --with-openssl=auto/lib/tongsuo "
# LIB_SRC_PATH=" --with-openssl=auto/lib/tongsuo"
flags=" $NJET_MODULES $PATH_INFO $LIB_SRC_PATH --with-debug --build=$git_tag --with-stream --with-http_addition_module --with-http_auth_request_module --with-http_dav_module --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-http_v3_module --with-mail --with-mail_ssl_module  --with-stream_realip_module --with-stream_ssl_module --with-stream_ssl_preread_module  --with-cc=/usr/bin/cc"
LD_OPT="-fsanitize=address -static-libgcc -static-libasan -ldl -lm "
CC_OPT="-O0 -ggdb -fsanitize=address -fno-omit-frame-pointer -static-libgcc -static-libasan -Wall -Wextra -Wshadow"
#LD_OPT="-ldl -lm "
#CC_OPT="-O0 -ggdb"

#api doc make tar file
doctar=doc.tar

if [ -f $doctar ]
then
   rm $doctar
fi

if [ -f $doctar.gz ]
then
   rm $doctar.gz
fi
tar cvf $doctar doc
gzip $doctar
xxd -i $doctar.gz > src/http/njt_doc_gz.h
if [ -f $doctar ]
then
   rm $doctar
fi

if [ -f $doctar.gz ]
then
   rm $doctar.gz
fi

cdir=`cd $(dirname $0); pwd`
(
    cd $cdir
    set -e
    for option; do
        case $option in
            conf*)
                if [ ! -f luajit/src/libluajit-5.1.so ]; then
                    cd luajit;make;cd -;
                    cp -f luajit/src/libluajit.so luajit/src/libluajit-5.1.so
                fi

                # ./configure --with-openssl=/root/download/openssl-openssl-3.0.8-quic1  $flags --with-openssl-opt='--strict-warnings' --with-cc-opt="$CC_OPT" --with-ld-opt="$LD_OPT"
                ./configure --with-openssl=auto/lib/tongsuo $flags --with-openssl-opt='--strict-warnings enable-ntls' --with-ntls --with-cc-opt="$CC_OPT" --with-ld-opt="$LD_OPT"
                ;;
            make)
                make
                ;;
            install)
                if [ ! -d /etc/njet/luajit ]; then
                    cd luajit;make install;cd -;
                    cp -a /etc/njet/luajit/lib/libluajit-5.1.* /usr/local/lib/
		fi
                if [ ! -d /etc/njet/lualib ]; then
		    cp -fr lualib /etc/njet/lualib
                fi
                cd auto/lib/keepalived; make install; cd -;
                make install
		mkdir /etc/njet/data
		chmod 777 -R /etc/njet/data  /etc/njet/logs
                ;;
            clean)
                rm -rf auto/lib/njetmq/build
                rm auto/lib/keepalived/Makefile
                make clean
                ;;
            release)
                if [ -f ./objs/njet ]; then
                    make clean
                fi
                ./configure $flags
                 make;
                cp objs/njet objs/njet.debug
                objcopy --strip-unneeded ./objs/njet
                ;;
            modules)
                if [ -f ./objs/njet ]; then
                    make clean
                fi
                ./configure $module_flags
                 make modules;
                 ;;
            *)
                echo "$0 [conf[igure]|make|install|clean|release]"
                ;;
        esac
    done
    set +e
)
