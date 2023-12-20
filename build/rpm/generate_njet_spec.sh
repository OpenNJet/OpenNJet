#!/usr/bin/env bash


NJT_VERSION=`grep "define NJT_VERSION" ../../src/core/njet.h |awk '{print $3}' |sed 's/"//g'`

sed -e "s/{{NJT_VERSION}}/$NJT_VERSION/g" -e "s/{{NJT_BUILD_OPT}}/$NJT_BUILD_OPT/g" < njet.spec.tmpl > njet.spec
