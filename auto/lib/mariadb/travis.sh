#!/bin/bash

set -e

export CC_DIR=/home/travis/build/mariadb-corporation/mariadb-connector-c
if [ -n "$server_branch" ] ; then

  ###################################################################################################################
  # run server test suite
  ###################################################################################################################
  echo "run server test suite"

  # change travis localhost to use only 127.0.0.1
  sudo sed -i 's/127\.0\.1\.1 localhost/127.0.0.1 localhost/' /etc/hosts
  sudo tail /etc/hosts

  # get latest server
  git clone -b ${server_branch} https://github.com/mariadb/server ../workdir-server --depth=1

  cd ../workdir-server
  export SERVER_DIR=$PWD

  # don't pull in submodules. We want the latest C/C as libmariadb
  # build latest server with latest C/C as libmariadb
  # skip to build some storage engines to speed up the build

  mkdir bld
  cd bld
  cmake .. -DPLUGIN_MROONGA=NO -DPLUGIN_ROCKSDB=NO -DPLUGIN_SPIDER=NO -DPLUGIN_TOKUDB=NO
  echo "PR:${TRAVIS_PULL_REQUEST} TRAVIS_COMMIT:${TRAVIS_COMMIT}"
  if [ -n "$TRAVIS_PULL_REQUEST" ] && [ "$TRAVIS_PULL_REQUEST" != "false" ] ; then
    # fetching pull request
    echo "fetching PR"
  else
    echo "checkout commit"
  fi

  cp $CC_DIR/* $SERVER_DIR/libmariadb -r
  cd $SERVER_DIR
  git add libmariadb

  cd $SERVER_DIR/bld
  make -j9

  cd mysql-test/
  ./mysql-test-run.pl --suite=main ${TEST_OPTION} --parallel=auto --skip-test=session_tracker_last_gtid

else

  ###################################################################################################################
  # run connector test suite
  ###################################################################################################################
  echo "run connector test suite"

  mkdir bld
  cd bld
  cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCERT_PATH=${SSLCERT}

  if [ "$TRAVIS_OS_NAME" = "windows" ] ; then
    echo "build from windows"
    set MARIADB_CC_TEST=1
    set MYSQL_TEST_DB=testc
    set MYSQL_TEST_TLS=%TEST_REQUIRE_TLS%
    set MYSQL_TEST_USER=%TEST_DB_USER%
    set MYSQL_TEST_HOST=%TEST_DB_HOST%
    set MYSQL_TEST_PASSWD=%TEST_DB_PASSWORD%
    set MYSQL_TEST_PORT=%TEST_DB_PORT%
    set MYSQL_TEST_TLS=%TEST_REQUIRE_TLS%
    cmake --build . --config RelWithDebInfo
  else
    echo "build from linux"
    export MARIADB_CC_TEST=1
    export MYSQL_TEST_USER=$TEST_DB_USER
    export MYSQL_TEST_HOST=$TEST_DB_HOST
    export MYSQL_TEST_PASSWD=$TEST_DB_PASSWORD
    export MYSQL_TEST_PORT=$TEST_DB_PORT
    export MYSQL_TEST_DB=testc
    export MYSQL_TEST_TLS=$TEST_REQUIRE_TLS
    export SSLCERT=$TEST_DB_SERVER_CERT
    export MARIADB_PLUGIN_DIR=$PWD

    echo "MYSQL_TEST_PLUGINDIR=$MYSQL_TEST_PLUGINDIR"
    if [ -n "$MYSQL_TEST_SSL_PORT" ] ; then
      export MYSQL_TEST_SSL_PORT=$MYSQL_TEST_SSL_PORT
    fi
    export MYSQL_TEST_TLS=$TEST_REQUIRE_TLS
    export SSLCERT=$TEST_DB_SERVER_CERT
    if [ -n "$MYSQL_TEST_SSL_PORT" ] ; then
      export MYSQL_TEST_SSL_PORT=$MYSQL_TEST_SSL_PORT
    fi
    make
  fi

  ls -lrt

  openssl ciphers -v
  cd unittest/libmariadb
  ctest -V
fi
