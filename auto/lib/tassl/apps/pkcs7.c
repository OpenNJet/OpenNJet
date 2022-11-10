/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "apps.h"
#include "progs.h"
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <crypto/sm2.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_INFORM, OPT_OUTFORM, OPT_IN, OPT_OUT, OPT_NOOUT,
    OPT_TEXT, OPT_PRINT, OPT_PRINT_CERTS, OPT_ENGINE,
#ifndef OPENSSL_NO_CNSM
    OPT_IN_SIGN_KEY_FORM, OPT_IN_SIGN_KEY, 
    OPT_GMT0009, OPT_GMT0010, OPT_OUT_ENC_KEY,
    OPT_ENC_KEY_PRINT,
#endif
} OPTION_CHOICE;

const OPTIONS pkcs7_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"inform", OPT_INFORM, 'F', "Input format - DER or PEM"},
    {"in", OPT_IN, '<', "Input file"},
    {"outform", OPT_OUTFORM, 'F', "Output format - DER or PEM"},
    {"out", OPT_OUT, '>', "Output file"},
    {"noout", OPT_NOOUT, '-', "Don't output encoded data"},
    {"text", OPT_TEXT, '-', "Print full details of certificates"},
    {"print", OPT_PRINT, '-', "Print out all fields of the PKCS7 structure"},
    {"print_certs", OPT_PRINT_CERTS, '-',
     "Print_certs  print any certs or crl in the input"},
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
#ifndef OPENSSL_NO_CNSM
    {"in_sign_key_format", OPT_IN_SIGN_KEY_FORM, 'f', "GMT0009/0010 Input sign key format - DER or PEM or ENGINE"},
    {"in_sign_key", OPT_IN_SIGN_KEY, '<', "GMT0009/0010 Input the sign key"},
    {"GMT0009", OPT_GMT0009, '-', "GMT 0009 envelope key"},
    {"GMT0010", OPT_GMT0010, '-', "GMT 0010 pkcs7 envelope key"},
    {"out_enc_key", OPT_OUT_ENC_KEY, '<', "GMT0009/0010 Output the enc key"},
    {"enc_key_print", OPT_ENC_KEY_PRINT, '-', "GMT0009/0010 print enc key"},
#endif
    {NULL}
};

int pkcs7_main(int argc, char **argv)
{
    ENGINE *e = NULL;
    PKCS7 *p7 = NULL;
    BIO *in = NULL, *out = NULL;
    int informat = FORMAT_PEM, outformat = FORMAT_PEM;
#ifndef OPENSSL_NO_CNSM
    int in_sign_key_format = FORMAT_PEM;
    char *in_sign_key = NULL;
    char *out_enc_key = NULL;
    int GMT0009 = 0, GMT0010 = 0;
    int enc_key_print = 0;
    EVP_CIPHER_CTX *cipher_ctx = NULL;
    SM2_Enveloped_Key *sm2evpkey = NULL;
    EVP_PKEY *sign_pkey = NULL, *enc_pkey = NULL;
    EC_KEY *eckey = NULL;
    BIGNUM *eckey_pri = NULL;
    EC_POINT *eckey_pub = NULL;
    BIO *bio_key = NULL;
    size_t key_text_len;
    unsigned char key_text[128];
#endif
    char *infile = NULL, *outfile = NULL, *prog;
    int i, print_certs = 0, text = 0, noout = 0, p7_print = 0, ret = 1;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, pkcs7_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(pkcs7_options);
            ret = 0;
            goto end;
        case OPT_INFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &informat))
                goto opthelp;
            break;
        case OPT_OUTFORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER, &outformat))
                goto opthelp;
            break;
#ifndef OPENSSL_NO_CNSM
        case OPT_IN_SIGN_KEY_FORM:
            if (!opt_format(opt_arg(), OPT_FMT_PEMDER | OPT_FMT_ENGINE, &in_sign_key_format))
                goto opthelp;
            break;
        case OPT_IN_SIGN_KEY:
            in_sign_key = opt_arg();
            break;
        case OPT_OUT_ENC_KEY:
            out_enc_key = opt_arg();
            break;
        case OPT_GMT0009:
            GMT0009 = 1;
            break;
        case OPT_GMT0010:
            GMT0010 = 1;
            break;
        case OPT_ENC_KEY_PRINT:
            enc_key_print = 1;
            break;
#endif
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_PRINT:
            p7_print = 1;
            break;
        case OPT_PRINT_CERTS:
            print_certs = 1;
            break;
        case OPT_ENGINE:
            e = setup_engine(opt_arg(), 0);
            break;
        }
    }
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    in = bio_open_default(infile, 'r', informat);
    if (in == NULL)
        goto end;

#ifndef OPENSSL_NO_CNSM
    /* for decode GMT 0009/0010 envelop key
     * add by ysc at 20210309*/
    if( GMT0009 || GMT0010 )
    {
        sign_pkey = load_key(in_sign_key, in_sign_key_format, 1, NULL, e, "Private Key");
        if( NULL == sign_pkey )
        {
            BIO_printf(bio_err, "unable to load Key\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }

    if( GMT0009 )
    {
        if( informat == FORMAT_ASN1 )
        {
            sm2evpkey = ASN1_item_d2i_bio(ASN1_ITEM_rptr(SM2_Enveloped_Key), in, NULL);
        }
        else
        {
            BIO_printf(bio_err, "in format error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if( NULL == sm2evpkey )
        {
            BIO_printf(bio_err, "unable to load sm2evpkey object\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        bio_key = SM2_Enveloped_Key_dataDecode(sm2evpkey, sign_pkey );
        if( NULL == bio_key )
        {
            BIO_printf(bio_err, "unable to decode sm2evpkey object\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if( BIO_read_ex(bio_key, key_text, sizeof(key_text), &key_text_len) <= 0 )
        {
            BIO_printf(bio_err, "sm2evpkey data error\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        
        if( 32 != key_text_len )
        {
            BIO_printf(bio_err, "key length error\n");
            ERR_print_errors(bio_err);
            goto end;
        }
        
        if( BIO_get_cipher_status(bio_key) <= 0 )
        {
            BIO_printf(bio_err, "sm2evpkey cipher decrypt error\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
#endif

#ifndef OPENSSL_NO_CNSM
    if( !GMT0009 )
    {
#endif
        if (informat == FORMAT_ASN1)
          p7 = d2i_PKCS7_bio(in, NULL);
        else
          p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
        if (p7 == NULL) {
            BIO_printf(bio_err, "unable to load PKCS7 object\n");
            ERR_print_errors(bio_err);
            goto end;
        }
#ifndef OPENSSL_NO_CNSM
    }
#endif

#ifndef OPENSSL_NO_CNSM
    /* for decode GMT 0009/0010 envelop key
     * add by ysc at 20210309*/
    if( GMT0010 )
    {
        bio_key = PKCS7_dataDecode(p7, sign_pkey, NULL, 0);
        if( NULL == bio_key )
        {
            BIO_printf(bio_err, "unable to decode p7 object\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if( BIO_get_cipher_ctx(bio_key, &cipher_ctx) <= 0 )
        {
            BIO_printf(bio_err, "unable to get cipher ctx\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if( EVP_CIPHER_CTX_set_padding(cipher_ctx, 0) <= 0 )
        {
            BIO_printf(bio_err, "unable to set padding\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if( BIO_read_ex(bio_key, key_text, sizeof(key_text), &key_text_len) <= 0 )
        {
            BIO_printf(bio_err, "pkcs7 read BIO error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if( BIO_get_cipher_status(bio_key) <= 0 )
        {
            BIO_printf(bio_err, "pkcs7 cipher decrypt error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if( key_text_len >= 32 )
        {
            memcpy(key_text, key_text+key_text_len-32, 32);
            key_text_len = 32;
        }
        else
        {
            BIO_printf(bio_err, "pkcs7 data error\n");
            ERR_print_errors(bio_err);
            goto end;
        }
    }
#endif

    out = bio_open_default(outfile, 'w', outformat);
    if (out == NULL)
        goto end;

#ifndef OPENSSL_NO_CNSM
    if( GMT0009 || GMT0010 )
    {
        enc_pkey = EVP_PKEY_new();
        if( NULL == enc_pkey )
        {
            BIO_printf(bio_err, "pkey new error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        eckey = EC_KEY_new_by_curve_name(NID_sm2);
        if( NULL == eckey )
        {
            BIO_printf(bio_err, "eckey new error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        eckey_pri = BN_bin2bn(key_text, key_text_len, NULL);
        if( NULL == eckey_pri )
        {
            BIO_printf(bio_err, "eckey pri bin2bn error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if( EC_KEY_set_private_key(eckey, eckey_pri) <= 0 )
        {
            BIO_printf(bio_err, "eckey set pri error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        eckey_pub = EC_POINT_new(EC_KEY_get0_group(eckey));
        if( NULL == eckey_pub )
        {
            BIO_printf(bio_err, "eckey pub new error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if( EC_POINT_mul(EC_KEY_get0_group(eckey), eckey_pub, EC_KEY_get0_private_key(eckey), NULL, NULL, NULL) <= 0 )
        {
            BIO_printf(bio_err, "calc eckey pub error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if( EC_KEY_set_public_key(eckey, eckey_pub) <= 0 )
        {
            BIO_printf(bio_err, "eckey set pub error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if( EVP_PKEY_set1_EC_KEY( enc_pkey, eckey) <= 0 )
        {
            BIO_printf(bio_err, "evp pkey set eckey error\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        if( !noout )
        {
            if (outformat == FORMAT_ASN1)
            {
                if( !i2d_PrivateKey_bio(out, enc_pkey) )
                  goto end;
            }
            else
            {
                if( !PEM_write_bio_PrivateKey(out, enc_pkey, NULL, NULL, 0, NULL, NULL) )
                  goto end;
            }
        }

        if( enc_key_print )
        {
            if(EVP_PKEY_print_private(out, enc_pkey, 0, NULL) <= 0)
            {
                BIO_printf(bio_err, "enc pkey print error\n");
                ERR_print_errors(bio_err);
                goto end;
            }
        }
        
        if( e )
        {
            if( 65 != EC_POINT_point2oct(EC_KEY_get0_group(eckey), EC_KEY_get0_public_key(eckey), 
                            POINT_CONVERSION_UNCOMPRESSED, key_text+32, sizeof(key_text)-32, NULL) )
            {
                BIO_printf(bio_err, "EC_POINT_point2oct error\n");
                ERR_print_errors(bio_err);
                goto end; 
            }
            key_text_len += 65;

            if( ENGINE_convert_private_key(e, (const char *)key_text, key_text_len, (unsigned char *)out_enc_key, NULL) <= 0 )
            {
                BIO_printf(bio_err, "ENGINE convert private key\n");
                ERR_print_errors(bio_err);
                goto end;
            }
        }
    }
#endif

#ifndef OPENSSL_NO_CNSM
    if( !GMT0009 )
    {
#endif
        if (p7_print)
          PKCS7_print_ctx(out, p7, 0, NULL);

        if (print_certs) {
            STACK_OF(X509) *certs = NULL;
            STACK_OF(X509_CRL) *crls = NULL;

            i = OBJ_obj2nid(p7->type);
            switch (i) {
                case NID_pkcs7_signed:
                case NID_pkcs7_sm2_signed:
                    if (p7->d.sign != NULL) {
                        certs = p7->d.sign->cert;
                        crls = p7->d.sign->crl;
                    }
                    break;
                case NID_pkcs7_signedAndEnveloped:
                case NID_pkcs7_sm2_signedAndEnveloped:
                    if (p7->d.signed_and_enveloped != NULL) {
                        certs = p7->d.signed_and_enveloped->cert;
                        crls = p7->d.signed_and_enveloped->crl;
                    }
                    break;
                default:
                    break;
            }

            if (certs != NULL) {
                X509 *x;

                for (i = 0; i < sk_X509_num(certs); i++) {
                    x = sk_X509_value(certs, i);
                    if (text)
                      X509_print(out, x);
                    else
                      dump_cert_text(out, x);

                    if (!noout)
                      PEM_write_bio_X509(out, x);
                    BIO_puts(out, "\n");
                }
            }
            if (crls != NULL) {
                X509_CRL *crl;

                for (i = 0; i < sk_X509_CRL_num(crls); i++) {
                    crl = sk_X509_CRL_value(crls, i);

                    X509_CRL_print_ex(out, crl, get_nameopt());

                    if (!noout)
                      PEM_write_bio_X509_CRL(out, crl);
                    BIO_puts(out, "\n");
                }
            }

            ret = 0;
            goto end;
        }

        if (!noout) {
            if (outformat == FORMAT_ASN1)
              i = i2d_PKCS7_bio(out, p7);
            else
              i = PEM_write_bio_PKCS7(out, p7);

            if (!i) {
                BIO_printf(bio_err, "unable to write pkcs7 object\n");
                ERR_print_errors(bio_err);
                goto end;
            }
        }
#ifndef OPENSSL_NO_CNSM
    }
#endif
    ret = 0;

end:
    PKCS7_free(p7);
    release_engine(e);
#ifndef OPENSSL_NO_CNSM
    if( bio_key )
      BIO_free_all(bio_key);
    if( sm2evpkey )
      SM2_Enveloped_Key_free(sm2evpkey);
    if( sign_pkey )
      EVP_PKEY_free(sign_pkey);
    if( enc_pkey )
      EVP_PKEY_free(enc_pkey);
    if( eckey )
      EC_KEY_free(eckey);
    if( eckey_pri )
      BN_free(eckey_pri);
    if( eckey_pub )
      EC_POINT_free(eckey_pub);
#endif
    BIO_free(in);
    BIO_free_all(out);
    return ret;
}
