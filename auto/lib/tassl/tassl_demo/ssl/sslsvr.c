/*
 * ++
 * FACILITY:
 *
 *      Simplest TLS Server
 *
 * ABSTRACT:
 *
 *   This is an example of a SSL server with minimum functionality.
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
#define LF "\n"

#define RETURN_NULL(x) if ((x)==NULL) { ERR_print_errors_fp(stderr); exit(1); }
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err)!=1) { ERR_print_errors_fp(stderr); exit(1); }

#define USAGE "Usage : \n\
\t -h/--help \t\t Display this summary\n\
\t -p port \t\t listen port\n\
\t -e engine \t\t engine name\n\
\t -sc cert \t\t sign cert\n\
\t -sk key \t\t sign key\n\
\t -ec cert \t\t enc cert\n\
\t -ek key \t\t enc key\n\
\t -ca cert \t\t CA cert\n\
\t -ca_path path \t\t CA path\n\
\t -PSK_ID id \t\t use PSK identity\n\
\t -PSK psk \t\t use PSK\n\
\t -keylog log \t\t key log\n\
\t --DTLS \t\t use DTLS\n\
\t --verify \t\t verify peer\n"

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

static unsigned char *keylog_filename = NULL;

void keylog_cb(const SSL *ssl, const char *line)
{
    int ret;
    BIO *bio = NULL;

    if (NULL != keylog_filename) {
        bio = BIO_new_file(keylog_filename, "ab+");
        RETURN_NULL(bio);

        if( strlen(line) != BIO_write(bio, line, strlen(line))
                    || strlen(LF) != BIO_write(bio, LF, strlen(LF)) )
        {
            fprintf(stderr, "wire keylog file error\n");
            exit(1);
        }

        BIO_free(bio);
    }
}

static unsigned char *PSK_ID = NULL;
static unsigned char PSK[256] = {0};
static size_t PSK_LEN = 0;
int DTLS = 0;

int psk_cb(SSL *ssl,
            const unsigned char *identity,
            size_t identity_len,
            SSL_SESSION **sess)
{
    SSL_SESSION *session = NULL;

    if (!PSK_ID)
      goto error;

    if (identity_len != strlen(PSK_ID) ||
                0 != memcmp(identity, PSK_ID, identity_len))
      goto error;

    session = SSL_SESSION_new();
    if (session == NULL
                || !SSL_SESSION_set1_master_key(session, PSK,
                    PSK_LEN)
                || !SSL_SESSION_set_cipher(session, SSL_get_pending_cipher(ssl))
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
	short int s_port = DEFAULT_PORT;
    int opt = 1;
	int listen_sock = -1;
	int sock = -1;
    int len;
	struct sockaddr_in sa_serv;
	char buf[MAX_BUF_LEN];
    char *sign_cert = NULL, *sign_key = NULL;
    char *enc_cert = NULL, *enc_key = NULL;
    char *ca_cert = NULL, *ca_path = NULL;
    char *engine_name = NULL;
    ENGINE *engine = NULL;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
    BIO *bio = NULL;
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
        else if (!strcasecmp(argv[err], "-p"))
        {
            s_port = atoi(argv[++err]);
            if (s_port <= 0) s_port = DEFAULT_PORT;
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
        else
        {
            fprintf(stderr, "unknown options, use --help\n");
            exit(1);
        }
    }

    fprintf(stdout, "Start With\n\
                Listening Port %d\n\
                Sign Cert %s\n\
                Sign Key %s\n\
                Enc Cert %s\n\
                Enc Key %s\n\
                CA Cert %s\n\
                Engine %s\n\
                Verify Peer %s\n", 
                s_port, 
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
      ctx = SSL_CTX_new(DTLS_server_method()); 
    else
      ctx = SSL_CTX_new(TLS_server_method());
    RETURN_NULL(ctx);

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

    if( ca_cert || ca_path )
    {
		/* Load the CA certificate into the SSL_CTX structure */
		err = SSL_CTX_load_verify_locations(ctx, ca_cert, ca_path);
        RETURN_SSL(err);
    }

	if ( verify_peer )
	{
		/* Set to require peer (client) certificate verification */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

		/* Set the verification depth to 1 */
		SSL_CTX_set_verify_depth(ctx, 1);
	}

    /* ----------------------------------------------- */
    memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family      = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port        = htons(s_port);          /* Server Port number */
    
    if( DTLS )
    {
        /* DTLS use UDP */
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        RETURN_ERR(sock, "socket");
        
        /* bind server address */
        err = bind(sock, (struct sockaddr*)&sa_serv, sizeof(sa_serv));
	    RETURN_ERR(err, "bind");
    }
    else
    {
        /* TLS use TCP */
        listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        RETURN_ERR(listen_sock, "socket");

        /* reuse port */
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, ( void *)&opt, sizeof(opt));
        
        /* bind server address */
        err = bind(listen_sock, (struct sockaddr*)&sa_serv, sizeof(sa_serv));
	    RETURN_ERR(err, "bind");

        /* Wait for an incoming TCP connection. */
        err = listen(listen_sock, 5);
        RETURN_ERR(err, "listen");

        /* Socket for a TCP/IP connection is created */
        sock = accept(listen_sock, NULL, NULL);
        RETURN_ERR(sock, "accept");

        close(listen_sock);
    }
    /* ----------------------------------------------- */

    /* dont use MIDDLEBOX for DTLS13 */
    //if(DTLS)
      //SSL_CTX_clear_options(ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

    /* set keylog file, maybe use for wireshark */
    SSL_CTX_set_keylog_callback(ctx, keylog_cb);

    SSL_CTX_set_psk_find_session_callback(ctx, psk_cb);

	/* A SSL structure is created */
	ssl = SSL_new(ctx);
	RETURN_NULL(ssl);
    
    /* Assign the socket into the SSL structure*/
    if( DTLS )
    {
        bio = BIO_new_dgram(sock, BIO_NOCLOSE);
        RETURN_NULL(bio);
    }
    else
    {
        bio = BIO_new(BIO_s_socket());
        RETURN_NULL(bio);

        err = BIO_set_fd(bio, sock, BIO_NOCLOSE);
        RETURN_SSL(err);
    }

    SSL_set_bio(ssl, bio, bio);

	/* Perform SSL Handshake on the SSL server */
	err = SSL_accept(ssl);
    RETURN_SSL(err);

	/* Informational output (optional) */
	fprintf(stdout, "SSL connection using %s, %s\n", SSL_get_version(ssl), SSL_get_cipher(ssl));
	ShowCerts(ssl);	

    while(1) {
        /*------- DATA EXCHANGE - Receive message and send reply. -------*/
        /* Receive data from the SSL client */
        memset(buf, 0x00, sizeof(buf));
        len = SSL_read(ssl, buf, sizeof(buf) - 1);
        if( len <= 0 )
        {
            ERR_print_errors_fp(stderr);
            exit(1);
        }
        fprintf(stdout, "recv %d bytes : %s\n", len, buf);

#define SEND_DATA     "this message is from the SSL server!\n"
#define SEND_DATA_LEN strlen(SEND_DATA)
        /* Send data to the SSL client */
        if( SEND_DATA_LEN != SSL_write(ssl, SEND_DATA, SEND_DATA_LEN) )
        {
            ERR_print_errors_fp(stderr);
            exit(1);
        }
    }

	/*--------------- SSL closure ---------------*/
	/* Shutdown this side (server) of the connection. */
	SSL_shutdown(ssl);

	/* Terminate communication on a socket */
	close(sock);

err:
    if( engine )
    {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }
    
	/* Free the SSL structure */
	if (ssl) SSL_free(ssl);

	/* Free the SSL_CTX structure */
	if (ctx) SSL_CTX_free(ctx);

    /*for openssl memory debug*/
    //CRYPTO_mem_leaks_fp(stderr);
    /**************************/

	return 0;
}
