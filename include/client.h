#ifndef _CLIENT_H_
#define _CLIENT_H_

#include "api.h"
#include "ui.h"
#include "util.h"
#include "ssl-nonblock.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#define CA_CERT "clientkeys/ca-cert.pem"
#define TIMEOUT_SECONDS 15
#define SERVER "server.self.com"

struct client_state {
  struct api_state api;
  int eof;
  struct ui_state ui;
  int isLoggedIn;
  char *username;

  SSL_CTX *ssl_ctx;
  SSL *ssl;
  /* TODO client state variables go here */
};

#endif