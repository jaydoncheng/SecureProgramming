#ifndef _UTIL_H_
#define _UTIL_H_

#include <netinet/in.h>
#include <stdio.h>

int lookup_host_ipv4(const char *hostname, struct in_addr *addr);
int max(int x, int y);
int parse_port(const char *str, uint16_t *port_p);

#define DEBUG 1
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
