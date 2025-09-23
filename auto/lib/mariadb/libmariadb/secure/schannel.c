/************************************************************************************
  Copyright (C) 2014 MariaDB Corporation Ab

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Library General Public License for more details.

  You should have received a copy of the GNU Library General Public
  License along with this library; if not see <http://www.gnu.org/licenses>
  or write to the Free Software Foundation, Inc.,
  51 Franklin St., Fifth Floor, Boston, MA 02110, USA

 *************************************************************************************/
#include "ma_schannel.h"
#include "schannel_certs.h"
#include <string.h>

extern my_bool ma_tls_initialized;
char tls_library_version[] = "Schannel";

#define PROT_SSL3 1
#define PROT_TLS1_0 2
#define PROT_TLS1_2 4
#define PROT_TLS1_3 8

static struct
{
  DWORD cipher_id;
  DWORD protocol;
  const char *iana_name;
  const char *openssl_name;
  ALG_ID algs[4]; /* exchange, encryption, hash, signature */
}
cipher_map[] =
{
  {
    0x0002,
    PROT_TLS1_0 |  PROT_TLS1_2 | PROT_SSL3,
    "TLS_RSA_WITH_NULL_SHA", "NULL-SHA",
    { CALG_RSA_KEYX, 0, CALG_SHA1, CALG_RSA_SIGN }
  },
  {
    0x0004,
    PROT_TLS1_0 |  PROT_TLS1_2 | PROT_SSL3,
    "TLS_RSA_WITH_RC4_128_MD5", "RC4-MD5",
    { CALG_RSA_KEYX, CALG_RC4, CALG_MD5, CALG_RSA_SIGN }
  },
  {
    0x0005,
    PROT_TLS1_0 |  PROT_TLS1_2 | PROT_SSL3,
    "TLS_RSA_WITH_RC4_128_SHA", "RC4-SHA",
    { CALG_RSA_KEYX, CALG_RC4, CALG_SHA1, CALG_RSA_SIGN }
  },
  {
    0x000A,
    PROT_SSL3,
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "DES-CBC3-SHA",
    {CALG_RSA_KEYX, CALG_3DES, CALG_SHA1, CALG_DSS_SIGN}
  },
  {
    0x0013,
    PROT_TLS1_0 |  PROT_TLS1_2 | PROT_SSL3,
    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "EDH-DSS-DES-CBC3-SHA",
    { CALG_DH_EPHEM, CALG_3DES, CALG_SHA1, CALG_DSS_SIGN }
  },
  {
    0x002F,
    PROT_SSL3 | PROT_TLS1_0 | PROT_TLS1_2,
    "TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA",
    { CALG_RSA_KEYX, CALG_AES_128, CALG_SHA, CALG_RSA_SIGN}
  },
  {
    0x0032,
    PROT_TLS1_0 |  PROT_TLS1_2,
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "DHE-DSS-AES128-SHA",
    { CALG_DH_EPHEM, CALG_AES_128, CALG_SHA1, CALG_RSA_SIGN }
  },
  {
    0x0033,
    PROT_TLS1_0 |  PROT_TLS1_2,
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE-RSA-AES128-SHA",
    { CALG_DH_EPHEM, CALG_AES_128, CALG_SHA1, CALG_RSA_SIGN }
  },
  {
    0x0035,
    PROT_TLS1_0 |  PROT_TLS1_2,
    "TLS_RSA_WITH_AES_256_CBC_SHA", "AES256-SHA",
    { CALG_RSA_KEYX, CALG_AES_256, CALG_SHA1, CALG_RSA_SIGN }
  },
  {
    0x0038,
    PROT_TLS1_0 |  PROT_TLS1_2,
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "DHE-DSS-AES256-SHA",
    { CALG_DH_EPHEM, CALG_AES_256, CALG_SHA1, CALG_DSS_SIGN }
  },
  {
    0x0039,
    PROT_TLS1_0 |  PROT_TLS1_2,
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE-RSA-AES256-SHA",
    { CALG_DH_EPHEM, CALG_AES_256, CALG_SHA1, CALG_RSA_SIGN }
  },
  {
    0x003B,
    PROT_TLS1_2,
    "TLS_RSA_WITH_NULL_SHA256", "NULL-SHA256",
    { CALG_RSA_KEYX, 0, CALG_SHA_256, CALG_RSA_SIGN }
  },
  {
    0x003C,
    PROT_TLS1_2,
    "TLS_RSA_WITH_AES_128_CBC_SHA256", "AES128-SHA256",
    { CALG_RSA_KEYX, CALG_AES_128, CALG_SHA_256, CALG_RSA_SIGN }
  },
  {
    0x003D,
    PROT_TLS1_2,
    "TLS_RSA_WITH_AES_256_CBC_SHA256", "AES256-SHA256",
    { CALG_RSA_KEYX, CALG_AES_256, CALG_SHA_256, CALG_RSA_SIGN }
  },
  {
    0x0040,
    PROT_TLS1_2,
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "DHE-DSS-AES128-SHA256",
    { CALG_DH_EPHEM, CALG_AES_128, CALG_SHA_256, CALG_DSS_SIGN }
  },
  {
    0x009C,
    PROT_TLS1_2,
    "TLS_RSA_WITH_AES_128_GCM_SHA256", "AES128-GCM-SHA256",
    { CALG_RSA_KEYX, CALG_AES_128, CALG_SHA_256, CALG_RSA_SIGN }
  },
  {
    0x009D,
    PROT_TLS1_2,
    "TLS_RSA_WITH_AES_256_GCM_SHA384", "AES256-GCM-SHA384",
    { CALG_RSA_KEYX, CALG_AES_256, CALG_SHA_384, CALG_RSA_SIGN }
  },
  {
    0x009E,
    PROT_TLS1_2,
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE-RSA-AES128-GCM-SHA256",
    { CALG_DH_EPHEM, CALG_AES_128, CALG_SHA_256, CALG_RSA_SIGN }
  },
  {
    0x009F,
    PROT_TLS1_2,
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE-RSA-AES256-GCM-SHA384",
    { CALG_DH_EPHEM, CALG_AES_256, CALG_SHA_384, CALG_RSA_SIGN }
  },
  {
    0xC027,
    PROT_TLS1_2,
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE-RSA-AES128-SHA256",
    { CALG_ECDH, CALG_AES_128, CALG_SHA_256, CALG_RSA_SIGN }
  },
  {
    0xC028,
    PROT_TLS1_2,
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE-RSA-AES256-SHA384",
    { CALG_ECDH, CALG_AES_256, CALG_SHA_384, CALG_RSA_SIGN }
  }
};

#define MAX_ALG_ID 50

extern void ma_schannel_set_sec_error(MARIADB_PVIO *pvio, DWORD ErrorNo);

/*
  Initializes SSL and allocate global
  context SSL_context

  SYNOPSIS
    ma_tls_start

  RETURN VALUES
    0  success
    1  error
*/
int ma_tls_start(char *errmsg, size_t errmsg_len)
{
  ma_tls_initialized = TRUE;
  return 0;
}

/*
   Release SSL and free resources
   Will be automatically executed by 
   mysql_server_end() function

   SYNOPSIS
     ma_tls_end()
       void

   RETURN VALUES
     void
*/
void ma_tls_end()
{
  return;
}

/* {{{ static int ma_tls_set_client_certs(MARIADB_TLS *ctls) */
static int ma_tls_set_client_certs(MARIADB_TLS *ctls,const CERT_CONTEXT **cert_ctx)
{
  MYSQL *mysql= ctls->pvio->mysql;
  char *certfile= mysql->options.ssl_cert,
       *keyfile= mysql->options.ssl_key;
  MARIADB_PVIO *pvio= ctls->pvio;
  char errmsg[256];

  if (!certfile && keyfile)
    certfile= keyfile;
  if (!keyfile && certfile)
    keyfile= certfile;

  if (!certfile)
    return 0;

  *cert_ctx = schannel_create_cert_context(certfile, keyfile, errmsg, sizeof(errmsg));
  if (!*cert_ctx)
  {
    pvio->set_error(pvio->mysql, CR_SSL_CONNECTION_ERROR, SQLSTATE_UNKNOWN, "SSL connection error: %s", errmsg);
    return 1;
  }

  return 0;
}
/* }}} */

/* {{{ void *ma_tls_init(MARIADB_TLS *ctls, MYSQL *mysql) */
void *ma_tls_init(MYSQL *mysql)
{
  SC_CTX *sctx = (SC_CTX *)LocalAlloc(LMEM_ZEROINIT, sizeof(SC_CTX));
  if (sctx)
  {
    SecInvalidateHandle(&sctx->CredHdl);
    SecInvalidateHandle(&sctx->hCtxt);
  }
  return sctx;
}
/* }}} */


/* 
  Maps between openssl suite names and schannel alg_ids.
  Every suite has 4 algorithms (for exchange, encryption, hash and signing).
  
  The input string is a set of suite names (openssl),  separated 
  by ':'
  
  The output is written into the array 'arr' of size 'arr_size'
  The function returns number of elements written to the 'arr'.
*/

static struct _tls_version {
  const char *tls_version;
  DWORD protocol;
} tls_version[]= {
    {"TLSv1.0", PROT_TLS1_0},
    {"TLSv1.2", PROT_TLS1_2},
    {"TLSv1.3", PROT_TLS1_3},
    {"SSLv3",   PROT_SSL3}
};

/* The following list was produced with OpenSSL 1.1.1j
   by executing `openssl ciphers -V`.  */
static struct {
  DWORD dwCipherSuite;
  const char *openssl_name;
} openssl_ciphers[] = {
  {0x002F, "AES128-SHA"},
  {0x0033, "DHE-RSA-AES128-SHA"},
  {0x0035, "AES256-SHA"},
  {0x0039, "DHE-RSA-AES256-SHA"},
  {0x003C, "AES128-SHA256"},
  {0x003D, "AES256-SHA256"},
  {0x0067, "DHE-RSA-AES128-SHA256"},
  {0x006B, "DHE-RSA-AES256-SHA256"},
  {0x008C, "PSK-AES128-CBC-SHA"},
  {0x008D, "PSK-AES256-CBC-SHA"},
  {0x0090, "DHE-PSK-AES128-CBC-SHA"},
  {0x0091, "DHE-PSK-AES256-CBC-SHA"},
  {0x0094, "RSA-PSK-AES128-CBC-SHA"},
  {0x0095, "RSA-PSK-AES256-CBC-SHA"},
  {0x009C, "AES128-GCM-SHA256"},
  {0x009D, "AES256-GCM-SHA384"},
  {0x009E, "DHE-RSA-AES128-GCM-SHA256"},
  {0x009F, "DHE-RSA-AES256-GCM-SHA384"},
  {0x00A8, "PSK-AES128-GCM-SHA256"},
  {0x00A9, "PSK-AES256-GCM-SHA384"},
  {0x00AA, "DHE-PSK-AES128-GCM-SHA256"},
  {0x00AB, "DHE-PSK-AES256-GCM-SHA384"},
  {0x00AC, "RSA-PSK-AES128-GCM-SHA256"},
  {0x00AD, "RSA-PSK-AES256-GCM-SHA384"},
  {0x00AE, "PSK-AES128-CBC-SHA256"},
  {0x00AF, "PSK-AES256-CBC-SHA384"},
  {0x00B2, "DHE-PSK-AES128-CBC-SHA256"},
  {0x00B3, "DHE-PSK-AES256-CBC-SHA384"},
  {0x00B6, "RSA-PSK-AES128-CBC-SHA256"},
  {0x00B7, "RSA-PSK-AES256-CBC-SHA384"},
  {0x1301, "TLS_AES_128_GCM_SHA256"},
  {0x1302, "TLS_AES_256_GCM_SHA384"},
  {0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
  {0xC009, "ECDHE-ECDSA-AES128-SHA"},
  {0xC00A, "ECDHE-ECDSA-AES256-SHA"},
  {0xC013, "ECDHE-RSA-AES128-SHA"},
  {0xC014, "ECDHE-RSA-AES256-SHA"},
  {0xC01D, "SRP-AES-128-CBC-SHA"},
  {0xC01E, "SRP-RSA-AES-128-CBC-SHA"},
  {0xC020, "SRP-AES-256-CBC-SHA"},
  {0xC021, "SRP-RSA-AES-256-CBC-SHA"},
  {0xC023, "ECDHE-ECDSA-AES128-SHA256"},
  {0xC024, "ECDHE-ECDSA-AES256-SHA384"},
  {0xC027, "ECDHE-RSA-AES128-SHA256"},
  {0xC028, "ECDHE-RSA-AES256-SHA384"},
  {0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256"},
  {0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384"},
  {0xC02F, "ECDHE-RSA-AES128-GCM-SHA256"},
  {0xC030, "ECDHE-RSA-AES256-GCM-SHA384"},
  {0xC035, "ECDHE-PSK-AES128-CBC-SHA"},
  {0xC036, "ECDHE-PSK-AES256-CBC-SHA"},
  {0xC037, "ECDHE-PSK-AES128-CBC-SHA256"},
  {0xC038, "ECDHE-PSK-AES256-CBC-SHA384"},
  {0xCCA8, "ECDHE-RSA-CHACHA20-POLY1305"},
  {0xCCA9, "ECDHE-ECDSA-CHACHA20-POLY1305"},
  {0xCCAA, "DHE-RSA-CHACHA20-POLY1305"},
  {0xCCAB, "PSK-CHACHA20-POLY1305"},
  {0xCCAC, "ECDHE-PSK-CHACHA20-POLY1305"},
  {0xCCAD, "DHE-PSK-CHACHA20-POLY1305"},
  {0xCCAE, "RSA-PSK-CHACHA20-POLY1305"}
};

static size_t set_cipher(char * cipher_str, DWORD protocol, ALG_ID *arr , size_t arr_size)
{
  char *token = strtok(cipher_str, ":");
  size_t pos = 0;

  while (token)
  {
    size_t i;

    for(i = 0; i < sizeof(cipher_map)/sizeof(cipher_map[0]) ; i++)
    {
      if((pos + 4 < arr_size && strcmp(cipher_map[i].openssl_name, token) == 0) ||
        (cipher_map[i].protocol <= protocol))
      {
        memcpy(arr + pos, cipher_map[i].algs, sizeof(ALG_ID)* 4);
        pos += 4;
        break;
      }
    }
    token = strtok(NULL, ":");
  }
  return pos;
}

my_bool ma_tls_connect(MARIADB_TLS *ctls)
{
  MYSQL *mysql;
  SCHANNEL_CRED Cred = {0};
  MARIADB_PVIO *pvio;
  my_bool rc= 1;
  SC_CTX *sctx;
  SECURITY_STATUS sRet;
  ALG_ID AlgId[MAX_ALG_ID];
  size_t i;
  DWORD protocol = 0;
  int verify_certs;
  const CERT_CONTEXT* cert_context = NULL;

  if (!ctls)
    return 1;

  pvio= ctls->pvio;
  sctx= (SC_CTX *)ctls->ssl;
  if (!pvio || !sctx)
    return 1;

  mysql= pvio->mysql;
  if (!mysql)
    return 1;

  /* Set cipher */
  if (mysql->options.ssl_cipher)
  {

   /* check if a protocol was specified as a cipher:
     * In this case don't allow cipher suites which belong to newer protocols
     * Please note: There are no cipher suites for TLS1.1
     */
    for (i = 0; i < sizeof(tls_version) / sizeof(tls_version[0]); i++)
    {
      if (!_stricmp(mysql->options.ssl_cipher, tls_version[i].tls_version))
        protocol |= tls_version[i].protocol;
    }
    memset(AlgId, 0, sizeof(AlgId));
    Cred.cSupportedAlgs = (DWORD)set_cipher(mysql->options.ssl_cipher, protocol, AlgId, MAX_ALG_ID);
    if (Cred.cSupportedAlgs)
    {
      Cred.palgSupportedAlgs = AlgId;
    }
    else if (!protocol)
    {
      ma_schannel_set_sec_error(pvio, SEC_E_ALGORITHM_MISMATCH);
      goto end;
    }
  }
  
  Cred.dwVersion= SCHANNEL_CRED_VERSION;

  Cred.dwFlags = SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;

  if (mysql->options.extension && mysql->options.extension->tls_version)
  {
    if (strstr(mysql->options.extension->tls_version, "TLSv1.0"))
      Cred.grbitEnabledProtocols|= SP_PROT_TLS1_0_CLIENT;
    if (strstr(mysql->options.extension->tls_version, "TLSv1.1"))
      Cred.grbitEnabledProtocols|= SP_PROT_TLS1_1_CLIENT;
    if (strstr(mysql->options.extension->tls_version, "TLSv1.2"))
      Cred.grbitEnabledProtocols|= SP_PROT_TLS1_2_CLIENT;
  }
  if (!Cred.grbitEnabledProtocols)
    Cred.grbitEnabledProtocols = SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT;


  if (ma_tls_set_client_certs(ctls, &cert_context))
    goto end;

  if (cert_context)
  {
    Cred.cCreds = 1;
    Cred.paCred = &cert_context;
  }
  sRet= AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
                                       NULL, &Cred, NULL, NULL, &sctx->CredHdl, NULL);
  if (sRet)
  {
    ma_schannel_set_sec_error(pvio, sRet);
    goto end;
  }
  if (ma_schannel_client_handshake(ctls) != SEC_E_OK)
    goto end;

   verify_certs =  mysql->options.ssl_ca || mysql->options.ssl_capath ||
     (mysql->client_flag & CLIENT_SSL_VERIFY_SERVER_CERT);

  if (verify_certs)
  {
    if (!ma_schannel_verify_certs(ctls, (mysql->client_flag & CLIENT_SSL_VERIFY_SERVER_CERT)))
      goto end;
  }

  rc = 0;

end:
  if (cert_context)
    schannel_free_cert_context(cert_context);
  return rc;
}

ssize_t ma_tls_read(MARIADB_TLS *ctls, const uchar* buffer, size_t length)
{
  SC_CTX *sctx= (SC_CTX *)ctls->ssl;
  MARIADB_PVIO *pvio= ctls->pvio;
  DWORD dlength= 0;
  SECURITY_STATUS status = ma_schannel_read_decrypt(pvio, &sctx->hCtxt, &dlength, (uchar *)buffer, (DWORD)length);
  if (status == SEC_I_CONTEXT_EXPIRED)
    return 0; /* other side shut down the connection. */
  if (status == SEC_I_RENEGOTIATE)
    return -1; /* Do not handle renegotiate yet */

  return (status == SEC_E_OK)? (ssize_t)dlength : -1;
}

ssize_t ma_tls_write(MARIADB_TLS *ctls, const uchar* buffer, size_t length)
{ 
  MARIADB_PVIO *pvio= ctls->pvio;
  ssize_t rc, wlength= 0;
  ssize_t remain= length;

  while (remain > 0)
  {
    if ((rc= ma_schannel_write_encrypt(pvio, (uchar *)buffer + wlength, remain)) <= 0)
      return rc;
    wlength+= rc;
    remain-= rc;
  }
  return length;
}

/* {{{ my_bool ma_tls_close(MARIADB_PVIO *pvio) */
my_bool ma_tls_close(MARIADB_TLS *ctls)
{
  SC_CTX *sctx= (SC_CTX *)ctls->ssl; 
  
  if (sctx)
  {
    LocalFree(sctx->IoBuffer);

    if (SecIsValidHandle(&sctx->CredHdl))
      FreeCredentialHandle(&sctx->CredHdl);

    if (SecIsValidHandle(&sctx->hCtxt))
      DeleteSecurityContext(&sctx->hCtxt);
  }
  LocalFree(sctx);
  return 0;
}
/* }}} */

int ma_tls_verify_server_cert(MARIADB_TLS *ctls)
{
  /* Done elsewhere */
  return 0;
}

static const char *cipher_name(const SecPkgContext_CipherInfo *CipherInfo)
{
  size_t i;

  for(i = 0; i < sizeof(openssl_ciphers)/sizeof(openssl_ciphers[0]) ; i++)
  {
    if (CipherInfo->dwCipherSuite == openssl_ciphers[i].dwCipherSuite)
      return openssl_ciphers[i].openssl_name;
  }
  return "";
};

const char *ma_tls_get_cipher(MARIADB_TLS *ctls)
{
  SecPkgContext_CipherInfo CipherInfo = { SECPKGCONTEXT_CIPHERINFO_V1 };
  SECURITY_STATUS sRet;
  SC_CTX *sctx;

  if (!ctls || !ctls->ssl)
    return NULL;

  sctx= (SC_CTX *)ctls->ssl;
  sRet= QueryContextAttributesA(&sctx->hCtxt, SECPKG_ATTR_CIPHER_INFO, (PVOID)&CipherInfo);

  if (sRet != SEC_E_OK)
    return NULL;

  return cipher_name(&CipherInfo);
}

unsigned int ma_tls_get_finger_print(MARIADB_TLS *ctls, char *fp, unsigned int len)
{
  SC_CTX *sctx= (SC_CTX *)ctls->ssl;
  PCCERT_CONTEXT pRemoteCertContext = NULL;
  if (QueryContextAttributes(&sctx->hCtxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)&pRemoteCertContext) != SEC_E_OK)
    return 0;
  CertGetCertificateContextProperty(pRemoteCertContext, CERT_HASH_PROP_ID, fp, (DWORD *)&len);
  CertFreeCertificateContext(pRemoteCertContext);
  return len;
}
