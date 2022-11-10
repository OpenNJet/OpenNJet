#!/bin/sh
LIB_DIR=/root/tassl/lib
INC_DIR=/root/tassl/include
PROGRAMES="sm2_evp_keygen sm2_evp_dec sm2_evp_enc_dec  sm2_evp_digest_sign_verify sm4_evp"

if [ $1"X" == "cleanX" ]; then
printf "cleaning the programe %s.....\n" $PROGRAMES
	rm -rf ${PROGRAMES} 
else
printf "compiling the programe.....\n"
gcc -ggdb3 -O0 -o sm2_evp_keygen sm2_evp_keygen.c -I${INC_DIR}  -L${LIB_DIR} -lssl -L${LIB_DIR} -lcrypto  -ldl -lpthread
gcc -ggdb3 -O0 -o sm2_evp_dec sm2_evp_dec.c -I${INC_DIR}  -L${LIB_DIR} -lssl -L${LIB_DIR} -lcrypto  -ldl -lpthread
gcc -ggdb3 -O0 -o sm2_evp_enc_dec sm2_evp_enc_dec.c -I${INC_DIR}  -L${LIB_DIR} -lssl -L${LIB_DIR} -lcrypto  -ldl -lpthread
gcc -ggdb3 -O0 -o sm2_evp_digest_sign_verify sm2_evp_digest_sign_verify.c -I${INC_DIR}  -L${LIB_DIR} -lssl -L${LIB_DIR} -lcrypto  -ldl -lpthread
gcc -ggdb3 -O0 -o sm4_evp sm4_evp.c -I${INC_DIR}  -L${LIB_DIR} -lssl -L${LIB_DIR} -lcrypto  -ldl -lpthread
fi
