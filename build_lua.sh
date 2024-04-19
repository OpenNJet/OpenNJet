#!/usr/bin/env bash

cd objs
cp -a ../scripts ./

for i in `find ./scripts -type f`; do
    LUA_PATH="../luajit/src/?.lua;;" ../luajit/src/luajit -bg $i $i 
done

#/usr/local/bin/luajit -bg scripts/http_register.lua objs/scripts/http_register.lua
#/usr/local/bin/luajit -bg scripts/register/adc_register.lua objs/scripts/register/adc_register.lua
