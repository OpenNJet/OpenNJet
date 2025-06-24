#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#define HMAC_KEY "xItp/m24fxz49pnm1wy"
#define HMAC_KEY_LEN 24
#define CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define CHARSET_LEN 62
#define MAX_PASSWORD_LEN 1024



void *
xmalloc (size_t size) {
  void *ptr;

  if ((ptr = malloc (size)) == NULL) {
      perror ("Unable to allocate memory - failed.");
      exit(EXIT_FAILURE);
  }

  return (ptr);
}


/* Encodes the given data with base64.
 *
 * On success, the encoded nul-terminated data, as a string is returned. */
char *
base64_encode (const void *buf, size_t size) {
  static const char base64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  char *str = (char *) xmalloc ((size + 3) * 4 / 3 + 1);

  char *p = str;
  const unsigned char *q = (const unsigned char *) buf;
  size_t i = 0;

  while (i < size) {
    int c = q[i++];
    c *= 256;
    if (i < size)
      c += q[i];
    i++;

    c *= 256;
    if (i < size)
      c += q[i];
    i++;

    *p++ = base64[(c & 0x00fc0000) >> 18];
    *p++ = base64[(c & 0x0003f000) >> 12];

    if (i > size + 1)
      *p++ = '=';
    else
      *p++ = base64[(c & 0x00000fc0) >> 6];

    if (i > size)
      *p++ = '=';
    else
      *p++ = base64[c & 0x0000003f];
  }

  *p = 0;

  return str;
}


// 生成随机密码
char* generate_random_password(int length) {
    char* password = malloc(length + 1);
    int i;
    if (!password) {
        perror("Failed to allocate memory for password");
        exit(EXIT_FAILURE);
    }

    unsigned char random_bytes[length];
    if (!RAND_bytes(random_bytes, length)) {
        fprintf(stderr, "Failed to generate random bytes\n");
        free(password);
        exit(EXIT_FAILURE);
    }
    for (i = 0; i < length; i++) {
        password[i] = CHARSET[random_bytes[i] % CHARSET_LEN];
    }
    password[length] = '\0';

    return password;
}


void hmac_sha1(const char *key, const char *data, unsigned char *result) {
    unsigned int len = SHA_DIGEST_LENGTH;
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, strlen(key), EVP_sha1(), NULL);
    HMAC_Update(ctx, (unsigned char*)data, strlen(data));
    HMAC_Final(ctx, result, &len);
    HMAC_CTX_free(ctx);
}


// 计算 HMAC-SHA1 并进行 Base64 编码
char* hash_password(const char* password) {
    unsigned char hash[SHA_DIGEST_LENGTH];

    hmac_sha1(HMAC_KEY, password, hash);

    // Base64 编码
    char* encoded_hash = base64_encode(hash, EVP_MD_size(EVP_sha1()));
    if (!encoded_hash) {
        fprintf(stderr, "Failed to encode hash to Base64\n");
        exit(EXIT_FAILURE);
    }

    return encoded_hash;
}

// 更新 SQLite3 数据库中的 passwd_hash
void update_passwd_hash(sqlite3* db, const char* password) {
    char* sql = "UPDATE api_user SET password = ? WHERE id = 1";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare SQL statement: %s\n", sqlite3_errmsg(db));
        exit(EXIT_FAILURE);
    }

    char* hashed_password = hash_password(password);
    sqlite3_bind_text(stmt, 1, hashed_password, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Failed to execute SQL statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        free(hashed_password);
        exit(EXIT_FAILURE);
    }

    sqlite3_finalize(stmt);
    free(hashed_password);

    printf("Password hash updated successfully for user_id=1, password: %s\n", password);
}

int main(int argc, char* argv[]) {
    if (argc != 2 && argc != 3) {
        fprintf(stderr, "Usage: %s <database_path> [password]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char* db_path = argv[1];
    char* password;

    if (argc == 2) {
        password = generate_random_password(16);
    } else {
        password = strdup(argv[2]);
        if (strlen(password) > MAX_PASSWORD_LEN) {
          fprintf(stderr, "password length exceed limit(1024): %s\n", password);
          free(password);
          exit(EXIT_FAILURE);
        }
    }

    sqlite3* db;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        free(password);
        exit(EXIT_FAILURE);
    }

    update_passwd_hash(db, password);

    sqlite3_close(db);
    printf("Generated password: %s\n", password);
    free(password);

    return 0;
}
