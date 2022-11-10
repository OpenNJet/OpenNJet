/*
 * ++
 * FACILITY:
 *
 *      Simplest TLS Client
 *
 * ABSTRACT:
 *
 *   This is an example of a SSL client with minimum functionality.
 *   The socket APIs are used to handle TCP/IP operations.
 *
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/engine.h"

#define DEFAULT_PORT 8020
#define MAX_BUF_LEN 4096

#define RETURN_NULL(x) if ((x)==NULL) { ERR_print_errors_fp(stderr); exit(1); }
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err)!=1) { ERR_print_errors_fp(stderr); exit(1); }

#define USAGE "Usage : \n\
\t -h/--help \t\t Display this summary\n\
\t -s host:port\t\t server address\n\
\t -e engine \t\t engine name\n\
\t -sc cert \t\t sign cert\n\
\t -sk key \t\t sign key\n\
\t -ec cert \t\t enc cert\n\
\t -ek key \t\t enc key\n\
\t -ca cert \t\t CA cert\n\
\t -ca_path path \t\t CA path\n\
\t -PSK_ID id \t\t use PSK identity\n\
\t -PSK psk \t\t use PSK\n\
\t --verify \t\t verify peer\n\
\t --DTLS \t\t use DTLS\n\
\t --gmssl \t\t USE gmssl\n"

void ShowCerts(SSL * ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("对端证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        OPENSSL_free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        OPENSSL_free(line);
        X509_free(cert);
    } else
        printf("无对端证书信息！\n");
}

static unsigned char *PSK_ID = NULL;
static unsigned char PSK[256] = {0};
static size_t PSK_LEN = 0;
int DTLS = 0;

int psk_cb(SSL *ssl, const EVP_MD *md,
            const unsigned char **id,
            size_t *idlen,
            SSL_SESSION **sess)
{
    SSL_SESSION *session = NULL;
    const SSL_CIPHER *cipher = NULL;

    if (!PSK_ID)
      goto error;

    *id = PSK_ID;
    *idlen = strlen(PSK_ID);

    /* PSK Hash algorithm MUST compatible with cipher suite 
     * 0x1301 - TLS_AES_128_GCM_SHA256 
     * 0x1302 - TLS_AES_256_GCM_SHA384 
     * 0x00C6 - TLS_SM4_GCM_SM3
     * 0x00C7 - TLS_SM4_CCM_SM3 */
    cipher = SSL_CIPHER_find(ssl, "\x00\xC6");
    if (md != NULL && md != SSL_CIPHER_get_handshake_digest(cipher))
      goto error;

    session = SSL_SESSION_new();
    if (session == NULL
                || !SSL_SESSION_set1_master_key(session, PSK,
                    PSK_LEN)
                || !SSL_SESSION_set_cipher(session, cipher)
                || !SSL_SESSION_set_protocol_version(session, TLS1_3_VERSION))
      goto error;

    *sess = session; session = NULL;

error:
    if (session) SSL_SESSION_free(session);
    return 1;
}

int main(int argc, char **argv)
{
	int err;
	int verify_peer = 0; /* To verify peer certificate, set ON */
    int gmssl = 0; /* Use gmssl, set ON */
	char *host = NULL;
    int len;
    int sock = -1;;
	char buf[MAX_BUF_LEN];
    char *sign_cert = NULL, *sign_key = NULL;
    char *enc_cert = NULL, *enc_key = NULL;
    char *ca_cert = NULL, *ca_path = NULL;
    char *engine_name = NULL;
    ENGINE *engine = NULL;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
    BIO *bio = NULL;
    BIO_ADDR *peer = NULL;
    struct in_addr addr;
    char ip[32] = {0};
    unsigned char *psk = NULL;
    long psk_len = 0;

    /* for openssl memory debug */
    //CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    /**************************/

    /* options */
    for (err = 1; err < argc; err++)
    {
        if (!strcasecmp(argv[err], "--help") || !strcasecmp(argv[err], "-h") )
        {
            fprintf(stdout, "%s", USAGE);
            exit(0);
        }
        else if (!strcasecmp(argv[err], "-e"))
        {
            engine_name = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-sc"))
        {
            sign_cert = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-sk"))
        {
            sign_key = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-ec"))
        {
            enc_cert = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-ek"))
        {
            enc_key = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-ca"))
        {
            ca_cert = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-ca_path"))
        {
            ca_path = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-s"))
        {
            host = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-psk_id"))
        {
            PSK_ID = argv[++err];
        }
        else if (!strcasecmp(argv[err], "-psk"))
        {
            psk = OPENSSL_hexstr2buf(argv[++err], &psk_len);
            if (psk) {
                memcpy(PSK, psk, psk_len);
                PSK_LEN = psk_len;
                OPENSSL_free(psk); psk = NULL;
            }
        }
        else if (!strcasecmp(argv[err], "--verify"))
        {
            verify_peer = 1;
        }
        else if (!strcasecmp(argv[err], "--dtls"))
        {
            DTLS = 1;
        }
        else if (!strcasecmp(argv[err], "--gmssl"))
        {
            gmssl = 1;
        }
        else
        {
            fprintf(stderr, "unknown options, use --help\n");
            exit(1);
        }
    }

    fprintf(stdout, "Start With\n\
                Server Address %s\n\
                Sign Cert %s\n\
                Sign Key %s\n\
                Enc Cert %s\n\
                Enc Key %s\n\
                CA Cert %s\n\
                Engine %s\n\
                Verify Peer %s\n", 
                host, 
                sign_cert ? sign_cert : "null",
                sign_key ? sign_key : "null",
                enc_cert ? enc_cert : "null",
                enc_key ? enc_key : "null",
                ca_cert ? ca_cert : "null",
                engine_name ? engine_name : "null",
                verify_peer ? "True" : "False");

	/* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();

	/* Load the error strings for SSL & CRYPTO APIs */
	SSL_load_error_strings();

    /* Load engine if use it */
    if( NULL != engine_name )
    {
        engine = ENGINE_by_id(engine_name);
        RETURN_NULL(engine);

        err = ENGINE_init(engine);
        RETURN_SSL(err);
    }

    /* Create a SSL_CTX structure */
    if( DTLS )
    {
        ctx = SSL_CTX_new(DTLS_client_method());
        RETURN_NULL(ctx);
    }
    else
    {
        if( gmssl )
        {
            //we use GMTLSv1.1
            ctx = SSL_CTX_new(CNTLS_client_method());
            RETURN_NULL(ctx);
        }
        else
        {
            //we use TLSv1.2
            ctx = SSL_CTX_new(TLS_client_method());
            RETURN_NULL(ctx);
            err = SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
            RETURN_SSL(err);
        }
    }

    /* Load sign cert and sign key */
    if( NULL != sign_cert && NULL != sign_key )
    {
        EVP_PKEY *pkey = NULL;
        
        /* Load the sign certificate into the SSL_CTX structure */
        err = SSL_CTX_use_certificate_file(ctx, sign_cert, SSL_FILETYPE_PEM);
        RETURN_SSL(err);

        if( NULL != engine )
        {
            /* Load private key, maybe cipher key file or key index that generated by engine */
            pkey = ENGINE_load_private_key(engine, sign_key, NULL, NULL);
            RETURN_NULL(pkey);
        }
        else
        {
            /* Load common private key file*/
            BIO *in = NULL;

            in = BIO_new(BIO_s_file());
            RETURN_NULL(in);

            err = BIO_read_filename(in, sign_key);
            RETURN_SSL(err);

            pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
            RETURN_NULL(pkey);

            BIO_free(in);
        }

        /* Use the private-key corresponding to the sign certificate */
        err = SSL_CTX_use_PrivateKey(ctx, pkey);
        RETURN_SSL(err);

        /* Check if the certificate and private-key matches */
        err = SSL_CTX_check_private_key(ctx);
        RETURN_SSL(err);

        EVP_PKEY_free(pkey);
    }

    /* Load enc cert and enc key */
    if( NULL != enc_cert && NULL != enc_key )
    {
        EVP_PKEY *pkey = NULL;

        /* Load the encrypt certificate into the SSL_CTX structure */
        err = SSL_CTX_use_certificate_file(ctx, enc_cert, SSL_FILETYPE_PEM);
        RETURN_SSL(err);

        if( NULL != engine )
        {
            /* Load private key, maybe cipher key file or key index that generated by engine */
            pkey = ENGINE_load_private_key(engine, enc_key, NULL, NULL);
            RETURN_NULL(pkey);
        }
        else
        {
            /* Load common private key file*/
            BIO *in = NULL;

            in = BIO_new(BIO_s_file());
            RETURN_NULL(in);

            err = BIO_read_filename(in, enc_key);
            RETURN_SSL(err);

            pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
            RETURN_NULL(pkey);

            BIO_free(in);
        }

        /* Use the private-key corresponding to the encrypt certificate */
        err = SSL_CTX_use_PrivateKey(ctx, pkey);
        RETURN_SSL(err);

        /* Check if the encrypt certificate and private-key matches */
        err = SSL_CTX_check_private_key(ctx);
        RETURN_SSL(err);

        EVP_PKEY_free(pkey);
    }

	if ( NULL != ca_cert || NULL != ca_path )
	{
		/* Load the CA certificate into the SSL_CTX structure */
		err = SSL_CTX_load_verify_locations(ctx, ca_cert, ca_path);
        RETURN_SSL(err);
    }

	if ( verify_peer )
	{
		/* Set to verify peer certificate */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

		/* Set the verification depth to 1 */
		SSL_CTX_set_verify_depth(ctx, 1);
    }

    if( DTLS )
    {
        /* DTLS use UDP */
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        RETURN_ERR(sock, "socket");

        peer = BIO_ADDR_new();
        RETURN_NULL(peer);

        memcpy(ip, host, strchr(host, ':')-host);
        addr.s_addr = inet_addr(ip);
        err = BIO_ADDR_rawmake(peer, AF_INET, &addr, sizeof(addr), htons(atoi(strchr(host, ':')+1)));
        RETURN_SSL(err);

        bio = BIO_new_dgram(sock, BIO_CLOSE);
        RETURN_NULL(bio);

        err = BIO_dgram_set_peer(bio, peer);
        RETURN_SSL(err);
    }
    else
    {
        /* TLS use TCP, Connect to address:port */
        bio = BIO_new_connect(host);
        RETURN_NULL(bio);

        err = BIO_do_connect(bio);
        RETURN_SSL(err);
    }

    //if(DTLS)
    //{
        /* TLS13/DTLS13 PSK Hash algorithm MUST compatible with cipher suite */
        //err = SSL_CTX_set_ciphersuites(ctx, "TLS_SM4_GCM_SM3");
        //RETURN_SSL(err);
    //}

    /* dont use MIDDLEBOX for DTLS13 */
    //if(DTLS)
      //SSL_CTX_clear_options(ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

    SSL_CTX_set_psk_use_session_callback(ctx, psk_cb);

    ssl = SSL_new(ctx);
    RETURN_NULL(ssl);

    SSL_set_bio(ssl, bio, bio);

    err = SSL_connect(ssl);
    RETURN_SSL(err);

	/* Informational output (optional) */
	fprintf(stdout, "SSL connection using %s, %s\n", SSL_get_version(ssl), SSL_get_cipher(ssl));
	ShowCerts(ssl);	

    while(1) {
        /*------- DATA EXCHANGE - Receive message and send reply. -------*/
        memset(buf, 0x00, sizeof(buf));
        fgets(buf, sizeof(buf), stdin);
        if (SSL_write(ssl, buf, strlen(buf)) != strlen(buf))
        {
            ERR_print_errors_fp(stderr);
            exit(1);
        }

        /* Receive data from the SSL client */
        memset(buf, 0x00, sizeof(buf));
        len = SSL_read(ssl, buf, sizeof(buf) - 1);
        if( len <= 0 )
        {
            ERR_print_errors_fp(stderr);
            exit(1);
        }
        fprintf(stdout, "recv %d bytes : %s\n", len, buf);
    }

	/*--------------- SSL closure ---------------*/
	/* Shutdown this side (server) of the connection. */
	SSL_shutdown(ssl);

	/* Terminate communication on a socket */

err:
    if( engine )
    {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }

    if (peer) BIO_ADDR_free(peer);

	/* Free the SSL structure */
	if (ssl) SSL_free(ssl);

	/* Free the SSL_CTX structure */
	if (ctx) SSL_CTX_free(ctx);

    /*for openssl memory debug*/
    //CRYPTO_mem_leaks_fp(stderr);
    /**************************/

	return 0;
}
