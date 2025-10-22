#!/bin/bash

set -e

SCRIPT_NAME=$(basename "$0")

NJET_DEFAULT_LOG_PREFIX=/var/log/njet
NJET_PREFIX="${NJET_PREFIX:-/usr/local/njet}"
NJET_CONF_PATH="${NJET_CONF_PATH:-conf/njet.conf}"
NJET_SBIN_PATH="${NJET_SBIN_PATH:-$NJET_PREFIX/sbin/njet}"
NJET_MODULES_PATH="${NJET_MODULES_PATH:-$NJET_PREFIX/modules}"
NJET_ERROR_LOG_PATH="${NJET_ERROR_LOG_PATH:-$NJET_DEFAULT_LOG_PREFIX/logs/error.log}"
# NJT_PID_PATH="${NJT_PID_PATH:-$NJET_DEFAULT_LOG_PREFIX/logs/njet.pid}"
# NJT_LOCK_PATH="${NJT_LOCK_PATH:-$NJET_DEFAULT_LOG_PREFIX/logs/njet.lock}"
# NJT_HTTP_LOG_PATH="${NJT_HTTP_LOG_PATH:-$NJET_DEFAULT_LOG_PREFIX/logs/access.log}"
if [ $NJET_DATA_PREFIX_PATH ]; then
    NJET_REAL_DATA_PREFIX_PATH=$NJET_DATA_PREFIX_PATH/njet
else
    NJET_REAL_DATA_PREFIX_PATH=$NJET_PREFIX
fi


# NJET_ERROR_LOG_PATH="${NJET_ERROR_LOG_PATH:-$NJET_PREFIX/logs/error.log}"
# NJT_PID_PATH="${NJT_PID_PATH:-$NJET_PREFIX/logs/njet.pid}"
# NJT_LOCK_PATH="${NJT_LOCK_PATH:-$NJET_PREFIX/logs/njet.lock}"
# NJT_HTTP_LOG_PATH="${NJT_HTTP_LOG_PATH:-$NJET_PREFIX/logs/access.log}"
# NJT_HTTP_CLIENT_TEMP_PATH="${NJT_HTTP_CLIENT_TEMP_PATH:-$NJET_PREFIX/client_body_temp}"
# NJT_HTTP_PROXY_TEMP_PATH="${NJT_HTTP_PROXY_TEMP_PATH:-$NJET_PREFIX/proxy_temp}"
# NJT_HTTP_FASTCGI_TEMP_PATH="${NJT_HTTP_FASTCGI_TEMP_PATH:-$NJET_PREFIX/fastcgi_temp}"
# NJT_HTTP_UWSGI_TEMP_PATH="${NJT_HTTP_UWSGI_TEMP_PATH:-$NJET_PREFIX/uwsgi_temp}"
# NJT_HTTP_SCGI_TEMP_PATH="${NJT_HTTP_SCGI_TEMP_PATH:-$NJET_PREFIX/scgi_temp}"


show_help() {
    cat << EOF
Usage: ${SCRIPT_NAME} [-h|--help] [-t <COMMITID>] [-d] [--with_tongsuo_8_4(default)|--with_tongsuo_8_3] [conf|make|install|clean]

Options:
  -h, --help            显示此帮助信息并退出
  -t, COMMITID          指定COMMITID
  -d, --debug           编译DEBUG版本
  --with_tongsuo_8_4    指定tongsuo 8.4版本 (默认使用该tongsuo版本)
  --with_tongsuo_8_3    指定tongsuo 8.3版本

Arguments:
  conf                  重新生成所有配置
  make                  编译OpenNjet源码
  install               安装OpenNjet
  clean                 clean目标输出

Examples:
  ${SCRIPT_NAME} -d conf make  debug版本,重新生成所有配置并进行编译
  ${SCRIPT_NAME} conf make     release版本,重新生成所有配置并进行编译
  ${SCRIPT_NAME} -d make       debug版本,不用重新生成所有配置直接进行编译
  ${SCRIPT_NAME} make          release版本,不用重新生成所有配置直接进行编译
  ${SCRIPT_NAME} --help        显示此帮助信息

如果要指定相关资源path路径, 请使用如下变量配置(如未明确指定,则会使用NJET_PREFIX作为目录前缀):
  NJET_PREFIX                        设置安装目录前缀(默认/usr/local/njet)
  NJET_SBIN_PATH                     设置njet二进制文件路径(默认$NJET_PREFIX/sbin/njet)
  NJET_DATA_PREFIX_PATH              设置data路径(默认$NJET_PREFIX)
  NJET_MODULES_PATH                  设置modules模块目录(默认$NJET_PREFIX/modules)
  NJET_CONF_PATH                     设置conf 文件路径(默认conf/njet.conf)
  NJET_ERROR_LOG_PATH                设置error日志文件路径(默认/var/log/njet/logs/error.log)
  NJT_PID_PATH                       设置njet.pid路径(默认logs/njet.pid)
  NJT_LOCK_PATH                      设置njet.lock路径(默认logs/njet.lock)
  NJT_HTTP_LOG_PATH                  设置http access log路径(默认logs/access.log)
  NJT_HTTP_CLIENT_TEMP_PATH          设置存储http 客户端请求体临时文件路径(默认client_body_temp)
  NJT_HTTP_PROXY_TEMP_PATH           设置存储http proxy 临时文件路径(默认proxy_temp)
  NJT_HTTP_FASTCGI_TEMP_PATH         设置存储http fastcgi 临时文件路径(默认fastcgi_temp)
  NJT_HTTP_UWSGI_TEMP_PATH           设置存储http uwsgi 临时文件路径(默认uwsgi_temp)
  NJT_HTTP_SCGI_TEMP_PATH            设置存储http scgi 临时文件路径(默认scgi_temp)

如果要指定相关path, 在执行脚本前设置对应path即可:
  NJET_PREFIX=/usr/local/njet NJET_SBIN_PATH=/usr/local/njet/sbin/njet  ${SCRIPT_NAME} -d conf make

EOF
}


GIT_TAG=""
DEBUG="False"
#WITH_TONGSUO_8_4="True"
WITH_TONGSUO_8_4="False"

# 定义短选项和长选项
OPTS="hdt:"
LONGOPTS="help,debug,with_tongsuo_8_3,with_tongsuo_8_4"

# 使用 getopt 解析参数
if ! parsed=$(getopt -o "$OPTS" --long "$LONGOPTS" -n "$0" -- "$@"); then
    echo "参数解析错误" >&2
    exit 1
fi

# 将解析后的参数设置为位置参数
eval set -- "$parsed"

# 处理选项
while true; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -d|--debug)
            DEBUG="True"
            shift
            ;;
        -t|--commitid)
            GIT_TAG="NJT_$2"
            shift 2
            ;;
        --with_tongsuo_8_4)
            WITH_TONGSUO_8_4="True"
            shift
            ;;
        --with_tongsuo_8_3)
            WITH_TONGSUO_8_4="False"
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "解析错误: $1" >&2
            exit 1
            ;;
    esac
done

# 剩余的参数是位置参数
EXTRA_PARAMS=("$@")


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


PATH_INFO=" --conf-path=$NJET_CONF_PATH \
    --prefix=$NJET_PREFIX \
    --sbin-path=$NJET_SBIN_PATH \
    --modules-path=$NJET_MODULES_PATH \
    --data-prefix-path=$NJET_REAL_DATA_PREFIX_PATH \
"

if [ $NJET_ERROR_LOG_PATH ]; then
    PATH_INFO="$PATH_INFO --error-log-path=$NJET_ERROR_LOG_PATH"
fi

if [ $NJT_PID_PATH ]; then
    PATH_INFO="$PATH_INFO --pid-path=$NJT_PID_PATH"
fi

if [ $NJT_LOCK_PATH ]; then
    PATH_INFO="$PATH_INFO --lock-path=$NJT_LOCK_PATH"
fi

if [ $NJT_HTTP_LOG_PATH ]; then
    PATH_INFO="$PATH_INFO --http-log-path=$NJT_HTTP_LOG_PATH"
fi

if [ $NJT_HTTP_CLIENT_TEMP_PATH ]; then
    PATH_INFO="$PATH_INFO --http-client-body-temp-path=$NJT_HTTP_CLIENT_TEMP_PATH"
fi

if [ $NJT_HTTP_PROXY_TEMP_PATH ]; then
    PATH_INFO="$PATH_INFO --http-proxy-temp-path=$NJT_HTTP_PROXY_TEMP_PATH"
fi

if [ $NJT_HTTP_FASTCGI_TEMP_PATH ]; then
    PATH_INFO="$PATH_INFO --http-fastcgi-temp-path=$NJT_HTTP_FASTCGI_TEMP_PATH"
fi

if [ $NJT_HTTP_UWSGI_TEMP_PATH ]; then
    PATH_INFO="$PATH_INFO --http-uwsgi-temp-path=$NJT_HTTP_UWSGI_TEMP_PATH"
fi

if [ $NJT_HTTP_SCGI_TEMP_PATH ]; then
    PATH_INFO="$PATH_INFO --http-scgi-temp-path=$NJT_HTTP_SCGI_TEMP_PATH"
fi


#   NJET_DATA_PREFIX_PATH                     设置data路径(默认$NJET_PREFIX/data)

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
    LD_OPT="-ldl -lm"
    if [ "$WITH_TONGSUO_8_4" = "True" ]; then
        CC_OPT="-O2 -g -Wno-implicit-fallthrough -Wno-deprecated-declarations -fPIC"
    else
        CC_OPT="-O2 -g -Wno-implicit-fallthrough -fPIC"
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
    for i in ${EXTRA_PARAMS[@]}; do
        case $i in
            conf*)
		test_cpu=`uname -m`
		if test "$test_cpu" = "loongarch64"; then
		  if [ -d luajit_loongarch64 ]; then		
	              mv luajit luajit_ori
		      mv luajit_loongarch64 luajit
		  fi 
	        fi

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
                make tools
                ;;
            install)
                make install
                cd luajit;PREFIX=${NJET_PREFIX} make install_lib;cd -;
		        mkdir -p ${DESTDIR}${NJET_PREFIX}/{lib,lualib}
                mkdir -p ${DESTDIR}${NJET_REAL_DATA_PREFIX_PATH}/apigw_data
		        cp -a build/api_gateway.db ${DESTDIR}${NJET_REAL_DATA_PREFIX_PATH}/apigw_data
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
                    cp -fr auto/lib/tcc-0.9.26/x86-64/libtcc1.a ${DESTDIR}${NJET_PREFIX}/lib/tcc/x86-64
                fi
                if [ -f auto/lib/tcc-0.9.26/arm64/libtcc1.a ]; then
                    mkdir -p ${DESTDIR}${NJET_PREFIX}/lib/tcc/arm64
                    cp -fr auto/lib/tcc-0.9.26/arm64/libtcc1.a  ${DESTDIR}${NJET_PREFIX}/lib/tcc/arm64
                fi
                if [ -f modules/njet-stream-proto-server-module/src/njt_tcc.h ]; then
                    mkdir -p ${DESTDIR}${NJET_PREFIX}/lib/tcc/include
                    cp -fr modules/njet-stream-proto-server-module/src/njt_tcc.h  ${DESTDIR}${NJET_PREFIX}/lib/tcc/include
                fi
                if [ -f modules/njet-stream-ws-module/src/http/proto_http_interface.h ]; then
                    mkdir -p ${DESTDIR}${NJET_PREFIX}/lib/tcc/include/http
                    cp -fr modules/njet-stream-ws-module/src/http/proto_http_interface.h  ${DESTDIR}${NJET_PREFIX}/lib/tcc/include/http
                fi
                if [ -f modules/njet-stream-ws-module/src/ws/proto_ws_interface.h ]; then
                    mkdir -p ${DESTDIR}${NJET_PREFIX}/lib/tcc/include/ws
                    cp -fr modules/njet-stream-ws-module/src/ws/proto_ws_interface.h  ${DESTDIR}${NJET_PREFIX}/lib/tcc/include/ws
                fi
                cp -rf auto/lib/tcc-0.9.26/include  ${DESTDIR}${NJET_PREFIX}/lib/tcc
                cp -fr auto/lib/tcc-0.9.26/tcclib.h  ${DESTDIR}${NJET_PREFIX}/lib/tcc/include

                cd auto/lib/luapkg; PREFIX=$NJET_PREFIX CDIR_linux=lualib/clib LDIR_linux=lualib/lib LUA_CMODULE_DIR=${PREFIX}/${CDIR_linux} LUA_MODULE_DIR=${PREFIX}/${LDIR_linux} make install; cd -;
                echo ${NJET_PREFIX}/lib > ${DESTDIR}/etc/ld.so.conf.d/njet.conf || echo "can't update ld.so.conf.d/njet.conf"
		        ldconfig || echo "can't run ldconfig"
                ;;
            clean)
                rm -rf auto/lib/njetmq/build
                rm -rf auto/lib/mariadb/build
                rm -f auto/lib/keepalived/Makefile
                cd auto/lib/modsecurity; make clean; cd -;
                cd auto/lib/librdkafka; make clean; cd -;
		cd auto/lib/luapkg; make clean; cd -;
		cd auto/lib/tcc-0.9.26; make clean; cd -;
                make clean
                ;;
            # release)
            #     if [ -f ./objs/njet ]; then
            #         make clean
            #     fi
            #     ./configure $flags
            #      make;
            #     cp objs/njet objs/njet.debug
            #     objcopy --strip-unneeded ./objs/njet
            #     ;;
            # modules)
            #     if [ -f ./objs/njet ]; then
            #         make clean
            #     fi
            #     ./configure $module_flags
            #      make modules;
            #      ;;
            *)
                show_help
                ;;
        esac
    done
    set +e
)

