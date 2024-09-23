#!/bin/bash

set -e
#NJET_CONF_PATH=/etc/njet/njet.conf
#NJET_PREFIX=/etc/njet
#NJET_SBIN_PATH=/usr/sbin/njet
#NJET_MODULES_PATH=/usr/lib/njet/modules

NJET_CONF_PATH=/usr/local/njet/conf/njet.conf
NJET_PREFIX=/usr/local/njet
NJET_SBIN_PATH=/usr/local/njet/sbin/njet
NJET_MODULES_PATH=/usr/local/njet/modules

GIT_TAG=""
DEBUG="False"
#WITH_TONGSUO_8_4="True"
WITH_TONGSUO_8_4="False"

while getopts "t:d-:" option; do
   case "${option}" in
      -)
         case "${OPTARG}" in
                with_tongsuo_8_4)
                    WITH_TONGSUO_8_4="True"
                    echo "Parsing option: '--${OPTARG}'" >&2;
                    ;;
                with_tongsuo_8_3)
                    WITH_TONGSUO_8_4="False"
                    echo "Parsing option: '--${OPTARG}'" >&2;
                    ;;
                *)
                    if [ "$OPTERR" = 1 ] && [ "${optspec:0:1}" != ":" ]; then
                        echo "Unknown option --${OPTARG}" >&2
                        echo "$0 [-t <COMMITID>] [-d] [--with_tongsuo_8_4(default)|--with_tongsuo_8_3] [conf[igure]|make|install|clean|release]"
                        exit
                    fi
                    ;;
            esac;;
      t) 
         GIT_TAG="NJT_${OPTARG}"
         ;;
      d) 
         DEBUG="True"
         ;;
     \?) # Invalid option
         echo "Error: Invalid option"
         echo "$0 [-t <COMMITID>] [-d] [--with_tongsuo_8_4(default)|--with_tongsuo_8_3] [conf[igure]|make|install|clean|release]"
         exit;;
   esac
done

shift "$(($OPTIND - 1))"

export LUAJIT_INC="`pwd`/luajit/src"
export LUAJIT_LIB="`pwd`/luajit/src"

static_modules=$(grep -v "^#" modules_static)
for module in $static_modules
do
   NJET_MODULES="$NJET_MODULES --add-module=${module}" 
done

dynamic_modules=$(grep -v "^#" modules_dynamic)
for module in $dynamic_modules
do
   NJET_MODULES="$NJET_MODULES --add-dynamic-module=${module}" 
done


PATH_INFO=" --conf-path=$NJET_CONF_PATH   --prefix=$NJET_PREFIX --sbin-path=$NJET_SBIN_PATH --modules-path=$NJET_MODULES_PATH "

if [ "$WITH_TONGSUO_8_4" = "True" ]; then
    LIB_SRC_PATH=" --with-openssl=auto/lib/Tongsuo "
else
    LIB_SRC_PATH=" --with-openssl=auto/lib/tongsuo "
fi

flags=" $NJET_MODULES $PATH_INFO $LIB_SRC_PATH --build=$GIT_TAG --with-stream --with-http_addition_module --with-http_auth_request_module --with-http_dav_module --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module  --with-http_sub_module --with-http_v2_module --with-http_v3_module --with-mail --with-mail_ssl_module  --with-stream_realip_module --with-stream_ssl_module --with-stream_ssl_preread_module  --with-cc=/usr/bin/cc --with-pcre"

if [ "$DEBUG" = "True" ]; then
    LD_OPT="-fsanitize=address -static-libgcc -static-libasan -ldl -lm"
    if [ "$WITH_TONGSUO_8_4" = "True" ]; then
        CC_OPT="-O0 -ggdb -Wno-deprecated-declarations -Wno-implicit-fallthrough -fsanitize=address -fno-omit-frame-pointer -static-libgcc -static-libasan -Wall -Wextra -Wshadow"
    else
        CC_OPT="-O0 -ggdb -fsanitize=address -fno-omit-frame-pointer -Wno-implicit-fallthrough -static-libgcc -static-libasan -Wall -Wextra -Wshadow"
    fi
    flags="$flags --with-debug"
else 
    LD_OPT="-ldl -lm -Wl,-z,relro -Wl,-z,now -pie"
    if [ "$WITH_TONGSUO_8_4" = "True" ]; then
        CC_OPT="-O2 -g -pipe -Wall -Wno-deprecated-declarations -Wno-implicit-fallthrough  -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -m64 -mtune=generic -fPIC"
    else
        CC_OPT="-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2  -Wno-implicit-fallthrough -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -m64 -mtune=generic -fPIC"
    fi
fi

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

                if [ "$WITH_TONGSUO_8_4" = "True" ]; then
                    ./configure --with-openssl=auto/lib/Tongsuo $flags --with-openssl-opt='--strict-warnings enable-ntls' --with-ntls --with-cc-opt="$CC_OPT" --with-ld-opt="$LD_OPT"
                else
                    ./configure --with-openssl=auto/lib/tongsuo $flags --with-openssl-opt='--strict-warnings enable-ntls' --with-ntls --with-cc-opt="$CC_OPT" --with-ld-opt="$LD_OPT"
                fi
                ;;
            make)
                make
                ;;
            install)
                make install
                cd luajit;PREFIX=${NJET_PREFIX} make install_lib;cd -;
		mkdir -p ${DESTDIR}${NJET_PREFIX}/{lib,lualib}
		cp -a lualib/lib ${DESTDIR}${NJET_PREFIX}/lualib/
		if [ -d auto/lib/modsecurity/src/.libs ]; then
                  cp -a auto/lib/modsecurity/src/.libs/libmodsecurity.so* ${DESTDIR}${NJET_PREFIX}/lib
                fi
		if [ -d auto/lib/keepalived/keepalived/emb/.libs ]; then
                  cp -a auto/lib/keepalived/keepalived/emb/.libs/libha_emb.so* ${DESTDIR}${NJET_PREFIX}/lib;
                fi 
		if [ -f auto/lib/librdkafka/build/src/librdkafka.so ]; then
                  cp -a auto/lib/librdkafka/build/src/librdkafka.so* ${DESTDIR}${NJET_PREFIX}/lib
                fi

		mkdir -p ${DESTDIR}${NJET_PREFIX}/lib/tcc
		if [ -f auto/lib/tcc-0.9.26/x86-64/libtcc1.a ]; then
			 mkdir -p ${DESTDIR}${NJET_PREFIX}/lib/tcc/x86-64
			cp -fr auto/lib/tcc-0.9.26/libtcc1.a ${DESTDIR}${NJET_PREFIX}/lib/tcc/x86-64
		fi
		if [ -f auto/lib/tcc-0.9.26/arm64/libtcc1.a ]; then
			 mkdir -p ${DESTDIR}${NJET_PREFIX}/lib/tcc/arm64
			cp -fr auto/lib/tcc-0.9.26/libtcc1.a  ${DESTDIR}${NJET_PREFIX}/lib/tcc/arm64
		fi
		if [ -f modules/njet-stream-proto-server-module/src/njt_tcc.h ]; then
			mkdir -p ${DESTDIR}${NJET_PREFIX}/lib/tcc/include
			cp -fr modules/njet-stream-proto-server-module/src/njt_tcc.h  ${DESTDIR}${NJET_PREFIX}/lib/tcc/include
		fi

		cp -rf auto/lib/tcc-0.9.26/include  ${DESTDIR}${NJET_PREFIX}/lib/tcc
		cp -fr auto/lib/tcc-0.9.26/tcclib.h  ${DESTDIR}${NJET_PREFIX}/lib/tcc/include

                cd auto/lib/luapkg; PREFIX=/usr/local CDIR_linux=njet/lualib/clib LDIR_linux=njet/lualib/lib LUA_CMODULE_DIR=${PREFIX}/${CDIR_linux} LUA_MODULE_DIR=${PREFIX}/${LDIR_linux} make install; cd -;
                echo ${NJET_PREFIX}/lib > ${DESTDIR}/etc/ld.so.conf.d/njet.conf || echo "can't update ld.so.conf.d/njet.conf"
		ldconfig || echo "can't run ldconfig"
                ;;
            clean)
                rm -rf auto/lib/njetmq/build
                rm -f auto/lib/keepalived/Makefile
                cd auto/lib/modsecurity; make clean; cd -;
                cd auto/lib/librdkafka; make clean; cd -;
		cd auto/lib/luapkg; make clean; cd -;
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
                echo "$0 [-t <COMMITID>] [-d]  [conf[igure]|make|install|clean|release]"
                ;;
        esac
    done
    set +e
)
