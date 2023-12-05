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

int lookup_host_ipv4(const char *hostname, struct in_addr *addr)
{
  struct hostent *host;

  assert(hostname);
  assert(addr);

  /* look up hostname, find first IPv4 entry */
  host = gethostbyname(hostname);
  while (host)
  {
    if (host->h_addrtype == AF_INET &&
        host->h_addr_list &&
        host->h_addr_list[0])
    {
      assert(host->h_length == sizeof(*addr));
      memcpy(addr, host->h_addr_list[0], sizeof(*addr));
      return 0;
    }
    host = gethostent();
  }

  fprintf(stderr, "error: unknown host: %s\n", hostname);
  return -1;
}

int max(int x, int y)
{
  return (x > y) ? x : y;
}

int parse_port(const char *str, uint16_t *port_p)
{
  char *endptr;
  long value;

  assert(str);
  assert(port_p);

  /* convert string to number */
  errno = 0;
  value = strtol(str, &endptr, 0);
  if (!value && errno)
    return -1;
  if (*endptr)
    return -1;

  /* is it a valid port number */
  if (value < 0 || value > 65535)
    return -1;

  *port_p = value;
  return 0;
}

int get_current_time(char *buf)
{
  time_t timer;
  struct tm *tm_info;
  timer = time(NULL);
  tm_info = localtime(&timer);
  strftime(buf, TIME_STR_SIZE, "%Y-%m-%d %H:%M:%S", tm_info);
  return 0;
}

void generate_salt(unsigned char *salt)
{
  if (RAND_bytes(salt, SALT_SIZE) != 1)
  {
    fprintf(stderr, "Error generating random salt\n");
    exit(EXIT_FAILURE);
  }
}

void generate_hash(const char *password, const unsigned char *salt, unsigned char *hash)
{
  EVP_MD_CTX *mdctx;

  mdctx = EVP_MD_CTX_new();

  if (mdctx == NULL)
  {
    // Handle error
    return;
  }
  if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
  {
    // Handle error
    EVP_MD_CTX_free(mdctx);
    return;
  }
  if (1 != EVP_DigestUpdate(mdctx, password, strlen(password)))
  {
    // Handle error
    EVP_MD_CTX_free(mdctx);
    return;
  }
  if (1 != EVP_DigestUpdate(mdctx, salt, SALT_SIZE))
  {
    // Handle error
    EVP_MD_CTX_free(mdctx);
    return;
  }
  if (1 != EVP_DigestFinal_ex(mdctx, hash, NULL))
  {
    EVP_MD_CTX_free(mdctx);
    return;
    // Handle error
  }

  EVP_MD_CTX_free(mdctx);
}

char *appendHyphenAndNewline(const char *input)
{
  char *result = (char *)malloc(strlen(input) + 3);

  if (result == NULL)
  {
    fprintf(stderr, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  strcpy(result, "-");
  strcat(result, input);
  strcat(result, "\n");

  return result;
}