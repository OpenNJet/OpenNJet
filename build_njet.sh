cd /njet_main

cd auto/lib
rm -rf pcre-8.45
unzip pcre-8.45.zip

cd /njet_main

sh build_cc.sh conf

sh build_cc.sh make



