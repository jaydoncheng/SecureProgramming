#ifndef _API_H_
#define _API_H_

#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define DEFAULT_MSG_LEN 128

struct api_msg {
  /* TODO add information about message */
  char *content;
  int cont_buf_len;
};

struct api_state {
  int fd;
  /* TODO add required fields */
};


int api_recv(SSL *ssl, struct api_state *state, struct api_msg *msg);
void api_recv_free(struct api_msg *msg);

void api_state_free(struct api_state *state);
void api_state_init(struct api_state *state, int fd);

/* TODO add API calls to send messages to perform client-server interactions */

#endif /* defined(_API_H_) */
