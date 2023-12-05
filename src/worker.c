#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>
#include <ctype.h>

#include "api.h"
#include "util.h"
#include "worker.h"
#include "database.h"
#include "client.h"

struct worker_state {
  struct api_state api;
  int eof;
  int server_fd;  /* server <-> worker bidirectional notification channel */
  int server_eof;
  struct client_state client;

  SSL_CTX *ssl_ctx;
  SSL *ssl;
};

/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state) {
  
  struct db_msg db_msg;
  read_latest_msg(&db_msg);
  char *msg = calloc(DB_MSG_SIZE + strlen(db_msg.content) + 3, sizeof(char));
  sprintf(msg, "%s %s: %s", db_msg.timestamp, db_msg.sender, db_msg.content);
  api_send(state->ssl, state->api.fd, msg, strlen(msg));
  
  return 0;
}

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
__attribute__((unused))
static int notify_workers(struct worker_state *state) {
  char buf = 0;
  ssize_t r;

  /* we only need to send something to notify the other workers,
   * data does not matter
   */
  r = write(state->server_fd, &buf, sizeof(buf));
  if (r < 0 && errno != EPIPE) {
    perror("error: write of server_fd failed");
    return -1;
  }
  return 0;
}

int send_chat_history(struct worker_state *state) {
  
  sqlite3 *db;
  char *msg;
  struct db_msg db_msg;
  sqlite3_stmt *stmt = NULL;
  int error = 0;

  fd_set writefds;
  FD_ZERO(&writefds);
  FD_SET(state->api.fd, &writefds);
  int fdmax = state->api.fd;

  if(sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
    return -1;
  }

  char *query = "SELECT * FROM messages WHERE "
                      "(receiver = 'Null') OR "
                      "(sender = @username AND receiver <> 'Null') OR "
                      "(receiver = @username) "
                      "ORDER BY id ASC";

  prepare_statement(db, query, &stmt);

  int usernameIndex = sqlite3_bind_parameter_index(stmt, "@username");
  sqlite3_bind_text(stmt, usernameIndex, state->client.username, -1, SQLITE_STATIC);


  while (sqlite3_step(stmt) == SQLITE_ROW) {
    db_to_msg(&db_msg, stmt);
    msg = calloc(DB_MSG_SIZE + strlen(db_msg.content) + 3, sizeof(char));
    sprintf(msg, "%s %s: %s", db_msg.timestamp, db_msg.sender, db_msg.content);
    

    int r = select(fdmax+1, NULL, &writefds, NULL, NULL);
    if (r < 0) {
      perror("dude im sot ired");
      return -1;
    }
    if (FD_ISSET(state->api.fd, &writefds)) {
      r = api_send(state->ssl, state->api.fd, msg, strlen(msg));
      free(msg);
    }
    
  }

  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return error;
}

/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 */
static int execute_request(struct worker_state *state, const struct api_msg *api_msg) {

  char cmd_fail_log[] = "error: command not currently available\n";
  char cmd_fail_rcv_not_found[] = "error: user not found\n";
  char cmd_reg_success[] = "registration succeeded\n";
  char cmd_invalid_format[] = "error: invalid command format\n";
  char cmd_invalid_cred[] = "error: invalid credentials\n";
  char cmd_auth_suc[] = "authentication succeeded\n";
  char cmd_user_alr_exst[64];
  char cmd_unknown_com[64];
  const char delim[] = " \n\t";

  /* sanitize input */
  char *buf = calloc(api_msg->cont_buf_len+2, sizeof(char));
  int l;
  for (l = 0; isprint(api_msg->content[l]); l++) 
    buf[l] = api_msg->content[l];

  buf[l] = '\n';
  buf[l+1] = '\0';
  
  if (strlen(buf) == 1) return 0;
  char *newBuf = removeLeadingWhitespace(buf);
  
  if (newBuf[0] == '/') {
    char *copy = calloc(strlen(newBuf), sizeof(char));
    strcpy(copy, newBuf);
    char *t = strtok(copy, delim);
    
    if (strcmp(t, "/register") == 0) {
      char username[32];
      char password[64];

      if(state->client.isLoggedIn == 1) {
        api_send(state->ssl, state->api.fd, cmd_fail_log, strlen(cmd_fail_log));
        goto cleanup;
      }

      if ((t = strtok(NULL, delim)) == NULL) goto invalid_format;
      strncpy(username, t, sizeof(username)-1);
      if ((t = strtok(NULL, delim)) == NULL) goto invalid_format;
      strncpy(password, t, sizeof(password)-1);
      if ((t = strtok(NULL, delim)) != NULL) goto invalid_format;

      printf("User wants to register with username %s and password %s\n", username, password);
      int rc = register_user(username, password);
      if (rc) {
        sprintf(cmd_fail, "error: user %s already exists\n", username);
        api_send(state->ssl, state->api.fd, cmd_fail, strlen(cmd_fail));
        }
      else {
        api_send(state->ssl, state->api.fd, cmd_success, strlen(cmd_success));
        state->client.username = strdup(username);
        state->client.isLoggedIn = 1;
        send_chat_history(state);
      }

      goto cleanup;

missing_args:
      api_send(state->ssl, state->api.fd, cmd_args, strlen(cmd_args));

    } else if(strcmp(t, "/login") == 0){
      if(state->client.isLoggedIn == 1) {
        api_send(state->ssl, state->api.fd, cmd_fail_log, strlen(cmd_fail_log));
        goto cleanup;
      }
      char username[32];
      char password[64];

      if ((t = strtok(NULL, delim)) == NULL) goto invalid_format;
      strncpy(username, t, sizeof(username)-1);
      if ((t = strtok(NULL, delim)) == NULL) goto invalid_format;
      strncpy(password, t, sizeof(password)-1);
      if ((t = strtok(NULL, delim)) != NULL) goto invalid_format;

      printf("User wants to log in with username %s and password %s\n", username, password);
      
      int rc = login_user(username, password);
      if (rc) api_send(state->ssl, state->api.fd, cmd_fail, strlen(cmd_fail));
      else {
        api_send(state->ssl, state->api.fd, cmd_success, strlen(cmd_success));
        state->client.username = strdup(username);
        state->client.isLoggedIn = 1;
        send_chat_history(state);
      }
      goto cleanup;

missing_args_login:
      api_send(state->ssl, state->api.fd, cmd_args, strlen(cmd_args));

    } else if(strcmp(t, "/users") == 0) {
      if(state->client.isLoggedIn != 1) {
        send(state->api.fd, cmd_fail_log, strlen(cmd_fail_log), 0);
        goto cleanup;
      }
      if ((t = strtok(NULL, delim)) != NULL) {
        send(state->api.fd, cmd_invalid_format, strlen(cmd_invalid_format), 0);
        goto cleanup;
      }
      print_users(state->api.fd);
      
    } else {
      char cmd_msg[64];
      sprintf(cmd_msg, "error: unknown command %s\n", t);
      api_send(state->ssl, state->api.fd, cmd_msg, strlen(cmd_msg));
    }
invalid_format:
    send(state->api.fd, cmd_invalid_format, strlen(cmd_invalid_format), 0);
cleanup:
    free(copy);
    return 0;
  }
  
  /* store messages in database */
  if(state->client.isLoggedIn != 1) {
    api_send(state->ssl, state->api.fd, cmd_fail_log, strlen(cmd_fail_log));
    free(buf);
    free(newBuf);
    return 0;
  }

  if(newBuf[0] == '@') {
    char *copy = calloc(strlen(newBuf), sizeof(char));
    strcpy(copy, newBuf);
    char *username = NULL;

    char *t = strtok(copy, delim);
    username = strdup(t + 1);

    printf("Username: %s\n", username);
    printf("Message content: %s\n", newBuf);

    sqlite3 *db = NULL;
    if (open_db(&db) != 0) {
      return -1;
    }
    if(user_exists(db, username)) {
      char *msg = getMessageAfterUser(newBuf, username);
      char *finalMsg = malloc(strlen(username) + strlen(msg) + 2);
      sprintf(finalMsg, "@%s %s",username, msg);
      handle_msg(state->client.username, username, finalMsg);
      free(msg);
      free(finalMsg);
      notify_workers(state);
    } else {
      api_send(state->ssl, state->api.fd, cmd_fail_rcv, strlen(cmd_fail_rcv));
    }
    free(copy);
  } else {
    handle_msg(state->client.username, "Null", newBuf);
    notify_workers(state);
  }

  free(newBuf);
  free(buf);
  return 0;
}

/**
 * @brief         Reads an incoming request from the client and handles it.
 * @param state   Initialized worker state
 */
static int handle_client_request(struct worker_state *state) {
  
  struct api_msg msg;
  int r, success = 1;

  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  r = api_recv(state->ssl, &state->api, &msg);
  if (r < 0) return -1;
  if (r == 0) {
    state->eof = 1;
    return 0;
  }

  
  /* execute request */
  if (execute_request(state, &msg) != 0) {
    success = 0;
  }

  /* clean up state associated with the message */
  api_msg_free(&msg);

  return success ? 0 : -1;
}

static int handle_s2w_read(struct worker_state *state) {
  
  char buf[256];
  ssize_t r;

  /* notification from the server that the workers must notify their clients
   * about new messages; these notifications are idempotent so the number
   * does not actually matter, nor does the data sent over the pipe
   */
  errno = 0;
  r = read(state->server_fd, buf, sizeof(buf));
  if (r < 0) {
    perror("error: read server_fd failed");
    return -1;
  }
  if (r == 0) {
    state->server_eof = 1;
    return 0;
  }

  /* notify our client */
  if (handle_s2w_notification(state) != 0) return -1;

  return 0;
}

/**
 * @brief Registers for: client request events, server notification
 *        events. In case of a client request, it processes the
 *        request and sends a response to client. In case of a server
 *        notification it notifies the client of all newly received
 *        messages.
 *
 */
static int handle_incoming(struct worker_state *state) {
  
  int fdmax, r, success = 1;
  fd_set readfds;

  assert(state);

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  /* wake on incoming messages from client */
  FD_SET(state->api.fd, &readfds);
  /* wake on incoming server notifications */
  if (!state->server_eof) FD_SET(state->server_fd, &readfds);
  fdmax = max(state->api.fd, state->server_fd);

  /* wait for at least one to become ready */
  r = select(fdmax+1, &readfds, NULL, NULL, NULL);
  if (r < 0) {
    if (errno == EINTR) return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  /* TODO once you implement encryption you may need to call ssl_has_data
   * here due to buffering (see ssl-nonblock example)
   */
  if (FD_ISSET(state->api.fd, &readfds)) {
    if (handle_client_request(state) != 0) success = 0;
  }
  if (FD_ISSET(state->server_fd, &readfds)) {
    if (handle_s2w_read(state) != 0) success = 0;
  }
  return success ? 0 : -1;
}

/**
 * @brief Initialize struct worker_state before starting processing requests.
 * @param state        worker state
 * @param connfd       connection file descriptor
 * @param pipefd_w2s   pipe to notify server (write something to notify)
 * @param pipefd_s2w   pipe to be notified by server (can read when notified)
 *
 */
static int worker_state_init(
  struct worker_state *state,
  int connfd,
  int server_fd) {

  /* initialize */
  memset(state, 0, sizeof(*state));
  state->server_fd = server_fd;

  /* set up API state */
  api_state_init(&state->api, connfd);

  state->ssl_ctx = SSL_CTX_new(TLS_server_method());
  state->ssl = SSL_new(state->ssl_ctx);

  SSL_use_certificate_file(state->ssl, "./serverkeys/server-ca-cert.pem", SSL_FILETYPE_PEM);
  SSL_use_PrivateKey_file(state->ssl, "./serverkeys/privkey-server.pem", SSL_FILETYPE_PEM);
  return 0;
}

/**
 * @brief Clean up struct worker_state when shutting down.
 * @param state        worker state
 *
 */
static void worker_state_free(
  struct worker_state *state) {
  SSL_free(state->ssl);
  SSL_CTX_free(state->ssl_ctx);
  /* clean up API state */
  api_state_free(&state->api);

  /* close file descriptors */
  close(state->server_fd);
  close(state->api.fd);
}

/**
 * @brief              Worker entry point. Called by the server when a
 *                     worker is spawned.
 * @param connfd       File descriptor for connection socket
 * @param pipefd_w2s   File descriptor for pipe to send notifications
 *                     from worker to server
 * @param pipefd_s2w   File descriptor for pipe to send notifications
 *                     from server to worker
 */
__attribute__((noreturn))
void worker_start(
  int connfd,
  int server_fd) {
  struct worker_state state;
  int success = 1;

  /* initialize worker state */
  if (worker_state_init(&state, connfd, server_fd) != 0) {
    goto cleanup;
  }


  set_nonblock(connfd);
  SSL_set_fd(state.ssl, connfd);
  ssl_block_accept(state.ssl, connfd); /* wtf does this do */

  //send_chat_history(&state);
  /* handle for incoming requests */
  while (!state.eof) {
    if (handle_incoming(&state) != 0) {
      success = 0;
      break;
    }
  }

cleanup:
  /* cleanup worker */
  worker_state_free(&state);

  exit(success ? 0 : 1);
}
