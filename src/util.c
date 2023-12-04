#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "util.h"

int lookup_host_ipv4(const char *hostname, struct in_addr *addr) {
  struct hostent *host;

  assert(hostname);
  assert(addr);

  /* look up hostname, find first IPv4 entry */
  host = gethostbyname(hostname);
  while (host) {
    if (host->h_addrtype == AF_INET &&
      host->h_addr_list &&
      host->h_addr_list[0]) {
      assert(host->h_length == sizeof(*addr));
      memcpy(addr, host->h_addr_list[0], sizeof(*addr));
      return 0;
    }
    host = gethostent();
  }

  fprintf(stderr, "error: unknown host: %s\n", hostname);
  return -1;
}

int max(int x, int y) {
  return (x > y) ? x : y;
}

int parse_port(const char *str, uint16_t *port_p) {
  char *endptr;
  long value;

  assert(str);
  assert(port_p);

  /* convert string to number */
  errno = 0;
  value = strtol(str, &endptr, 0);
  if (!value && errno) return -1;
  if (*endptr) return -1;

  /* is it a valid port number */
  if (value < 0 || value > 65535) return -1;

  *port_p = value;
  return 0;
}

int get_current_time(char *buf) {
  time_t timer;
  struct tm* tm_info;
  timer = time(NULL);
  tm_info = localtime(&timer);
  strftime(buf, TIME_STR_SIZE, "%Y-%m-%d %H:%M:%S", tm_info);
  return 0;
}

void generate_salt(unsigned char *salt) {
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        fprintf(stderr, "Error generating random salt\n");
        exit(EXIT_FAILURE);
    }
}

void generate_hash(const char *password, const unsigned char *salt, unsigned char *hash) {
    EVP_MD_CTX *mdctx;

    mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL) {
        // Handle error
        return;
    }
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        // Handle error
        EVP_MD_CTX_free(mdctx);
        return;
    }
    if (1 != EVP_DigestUpdate(mdctx, password, strlen(password))) {
        // Handle error
        EVP_MD_CTX_free(mdctx);
        return;
    }
    if (1 != EVP_DigestUpdate(mdctx, salt, SALT_SIZE)) {
        // Handle error
        EVP_MD_CTX_free(mdctx);
        return;
    }
    if (1 != EVP_DigestFinal_ex(mdctx, hash, NULL)) {
        // Handle error
    }

    EVP_MD_CTX_free(mdctx);
}

EVP_PKEY *rsa_read_pubkey_from_file(const char *path) {
    FILE *file = fopen(path, "r");
    EVP_PKEY *key = NULL;
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(
    &key, /* key stored here */
    "PEM", /* input type */
    NULL,
    "RSA", /* key type */
    EVP_PKEY_PUBLIC_KEY, /* pubkey or pub+privkey pair */
    NULL, NULL);
    OSSL_DECODER_from_fp(ctx, file);
    fclose(file);
    return key;
}


size_t rsa_encrypt(EVP_PKEY *pubkey, unsigned char *plaintext_in,
size_t plaintext_len, unsigned char **ciphertext_out) {
    /* initialization with random padding */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    /* determine buffer length */
    size_t ciphertext_len = 0;
    EVP_PKEY_encrypt(ctx,
    NULL, &ciphertext_len, /* NULL means get length */
    plaintext_in, plaintext_len); /* input plaintext */
    *ciphertext_out = malloc(ciphertext_len);
    /* perform decryption */
    EVP_PKEY_encrypt(ctx,
    *ciphertext_out, &ciphertext_len, /* output ciphertext */
    plaintext_in, plaintext_len /* input plaintext */);
    /* clean up */
    EVP_PKEY_CTX_free(ctx);
    return ciphertext_len;
}

EVP_PKEY *rsa_read_privkey_from_file(const char *path) {
    FILE *file = fopen(path, "r");
    EVP_PKEY *key = NULL;
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(
    &key, /* key stored here */
    "PEM", /* input type */
    NULL,
    "RSA", /* key type */
    EVP_PKEY_KEYPAIR, /* pubkey or pub+privkey pair */
    NULL, NULL);
    OSSL_DECODER_from_fp(ctx, file);
    fclose(file);
    return key;
}

size_t rsa_decrypt(EVP_PKEY *privkey, unsigned char *ciphertext_in,
    size_t ciphertext_len, unsigned char **plaintext_out) {
    /* initialization with random padding */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    /* determine buffer length */
    size_t plaintext_len = 0;
    EVP_PKEY_decrypt(ctx,
    NULL, &plaintext_len, /* NULL means get length */
    ciphertext_in, ciphertext_len); /* input ciphertext */
    *plaintext_out = malloc(plaintext_len);
    /* perform decryption */
    EVP_PKEY_decrypt(ctx,
    *plaintext_out, &plaintext_len, /* output plaintext */
    ciphertext_in, ciphertext_len /* input ciphertext */);
    /* clean up */
    EVP_PKEY_CTX_free(ctx);
    return plaintext_len;
}

RSA* generate_rsa_key_pair(int bits) {
    RSA *rsa_key = RSA_new();

    // if (rsa_key == NULL) {
    //     // Handle error
    //     return NULL;
    // }

    //(rsa pointer, size of the RSA key (2048 or 4096), exponent(NULL -> default value 65537), callback)
    if (!RSA_generate_key_ex(rsa_key, bits, NULL, NULL)) {
        // Handle error
        RSA_free(rsa_key);
        BN_free(e);
        return NULL;
    }

    BN_free(e);
    return rsa_key;
}

EVP_PKEY* extract_public_key(RSA* rsa_key) {
    EVP_PKEY* public_key = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(public_key, rsa_key)) {
        // Handle error
        EVP_PKEY_free(public_key);
        return NULL;
    }
    return public_key;
}

EVP_PKEY* extract_private_key(RSA* rsa_key) {
    EVP_PKEY* private_key = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(private_key, rsa_key)) {
        // Handle error
        EVP_PKEY_free(private_key);
        return NULL;
    }
    return private_key;
}