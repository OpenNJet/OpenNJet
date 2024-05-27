#!/usr/bin/env bash

export LUA_PATH="`pwd`/luajit/src/?.lua;;"
LUABIN=`pwd`/luajit/src/luajit 

cd objs
rm -rf scripts
cp -a ../scripts ./

#all files not under modules directory is using luajit to precompile to bytecode
for i in `find ./scripts -not -path "./scripts/modules*" -type f`; do
    $LUABIN -bg $i $i 
done

#for all the files under modules directory, compile each module and pack to .so 
cd ./scripts
mkdir -p so
rm -rf so/*
cd ./modules
mkdir -p objs
for mod in `ls *.lua`; do
  rm -rf objs/*
  MODNAME=${mod%.lua}
  if [ -d ./${MODNAME} ] ;then
    for i in `find ./${MODNAME} -type f` ; do
      obj_name=`echo $i | sed 's|^./||g' |sed 's|/|_|g' |sed 's|.lua$|.o|g'`
      mod_name=`echo $i | sed 's|^./||g' |sed 's|/|.|g' |sed 's|.lua$||g'`
      $LUABIN  -b $i  -n $mod_name objs/${obj_name}
    done
  fi
  $LUABIN -b ${MODNAME}.lua -n "${MODNAME}" objs/${MODNAME}.o
  cd objs
  gcc -shared -o ../../so/${MODNAME}.so *.o
  cd ..
done
cd ../../
rm -rf scripts/modules


