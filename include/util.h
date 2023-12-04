#ifndef _UTIL_H_
#define _UTIL_H_

#include <netinet/in.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include <openssl/rsa.h>


int lookup_host_ipv4(const char *hostname, struct in_addr *addr);
int max(int x, int y);
int parse_port(const char *str, uint16_t *port_p);
void generate_salt(unsigned char *salt);
void generate_hash(const char *password, const unsigned char *salt, unsigned char *hash);

int get_current_time(char *buf);
#define TIME_STR_SIZE 20

#define SALT_SIZE 16
#define HASH_SIZE SHA256_DIGEST_LENGTH

#define DEBUG 0
#define debug_print if(DEBUG) printf 
#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

#endif /* defined(_UTIL_H_) */
