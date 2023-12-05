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
  /* TODO worker state variables go here */
};

/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state) {
  /* TODO implement the function */
  
  struct db_msg db_msg;
  read_latest_msg(&db_msg);
  char *msg = calloc(DB_MSG_SIZE + strlen(db_msg.content) + 3, sizeof(char));
  sprintf(msg, "%s %s: %s", db_msg.timestamp, db_msg.sender, db_msg.content);
  send(state->api.fd, msg, strlen(msg), 0);
  
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
      r = send(state->api.fd, msg, strlen(msg), 0);
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

  /* sanitize input */
  char *buf = calloc(api_msg->cont_buf_len+2, sizeof(char));
  int l;
  for (l = 0; isprint(api_msg->content[l]); l++) 
    buf[l] = api_msg->content[l];
  
  buf[l] = '\n';
  buf[l+1] = '\0';
  if (strlen(buf) == 1) return 0;
  
  if (buf[0] == '/') {
    const char delim[] = " \n\t";
    char *copy = calloc(strlen(buf), sizeof(char));
    strcpy(copy, buf);
    char *t = strtok(copy, delim);
    
    if (strcmp(t, "/register") == 0) {
      if(state->client.isLoggedIn == 1) {
        send(state->api.fd, cmd_fail_log, strlen(cmd_fail_log), 0);
        goto cleanup;
      }
      char cmd_args[] = "error: invalid command format\n";
      char cmd_success[] = "registration succeeded\n";
      char cmd_fail[64];
      char username[32];
      char password[64];

      if ((t = strtok(NULL, delim)) == NULL) goto missing_args;
      strncpy(username, t, sizeof(username)-1);
      if ((t = strtok(NULL, delim)) == NULL) goto missing_args;
      strncpy(password, t, sizeof(password)-1);
      if ((t = strtok(NULL, delim)) != NULL) goto missing_args;

      printf("User wants to register with username %s and password %s\n", username, password);
      int rc = register_user(username, password);
      if (rc) {
        sprintf(cmd_fail, "error: user %s already exists\n", username);
        send(state->api.fd, cmd_fail, strlen(cmd_fail), 0);
        }
      else {
        send(state->api.fd, cmd_success, strlen(cmd_success), 0);
        state->client.username = strdup(username);
        state->client.isLoggedIn = 1;
        send_chat_history(state);
      }

      goto cleanup;

missing_args:
      send(state->api.fd, cmd_args, strlen(cmd_args), 0);

    } else if(strcmp(t, "/login") == 0){
      if(state->client.isLoggedIn == 1) {
        send(state->api.fd, cmd_fail_log, strlen(cmd_fail_log), 0);
        goto cleanup;
      }
      char cmd_args[] = "error: invalid command format\n";
      char cmd_success[] = "authentication succeeded\n";
      char cmd_fail[] = "error: invalid credentials\n";
      char username[32];
      char password[64];

      if ((t = strtok(NULL, delim)) == NULL) goto missing_args_login;
      strncpy(username, t, sizeof(username)-1);
      if ((t = strtok(NULL, delim)) == NULL) goto missing_args_login;
      strncpy(password, t, sizeof(password)-1);
      if ((t = strtok(NULL, delim)) != NULL) goto missing_args_login;

      printf("User wants to log in with username %s and password %s\n", username, password);
      int rc = login_user(username, password);
      if (rc) send(state->api.fd, cmd_fail, strlen(cmd_fail), 0);
      else {
        send(state->api.fd, cmd_success, strlen(cmd_success), 0);
        state->client.username = strdup(username);
        state->client.isLoggedIn = 1;
        send_chat_history(state);
      }
      goto cleanup;

missing_args_login:
      send(state->api.fd, cmd_args, strlen(cmd_args), 0);

    } else if(strcmp(t, "/users") == 0) {
      char cmd_args[] = "error: invalid command format\n";
      if(state->client.isLoggedIn != 1) {
        send(state->api.fd, cmd_fail_log, strlen(cmd_fail_log), 0);
        goto cleanup;
      }
      if ((t = strtok(NULL, delim)) != NULL) {
        send(state->api.fd, cmd_args, strlen(cmd_args), 0);
        goto cleanup;
      }
      print_users(state->api.fd);
    } else {
      printf("String started with /\n");
      char cmd_msg[64];
      sprintf(cmd_msg, "error: unknown command %s\n", t);
      send(state->api.fd, cmd_msg, strlen(cmd_msg), 0);
    }
cleanup:
    free(copy);
    return 0;
  }
  
  /* store public message in database */
  if(state->client.isLoggedIn != 1) {
    send(state->api.fd, cmd_fail_log, strlen(cmd_fail_log), 0);
    free(buf);
    return 0;
  }

  if(buf[0] == '@') {
    // char cmd_args[] = "@<username> <message>\n";
    char cmd_success[] = "Successfully sent private message\n";
    char cmd_fail_rcv[] = "error: user not found\n";

    const char delim[] = " \n\t";
    char *copy = calloc(strlen(buf), sizeof(char));
    strcpy(copy, buf);
    char username[32];
    char messageContent[256];

    char *space_position = strstr(copy, " ");
    size_t message_length = strlen(space_position + 1);
    strncpy(messageContent, space_position + 1, message_length);

    char *t = strtok(copy, delim);
    strncpy(username, t + 1, sizeof(username) - 1);

    printf("Username: %s\n", username);
    printf("Message content: %s\n", messageContent);

    if(handle_prv_msg(state->client.username, username, messageContent) == 0) {
      send(state->api.fd, cmd_success, strlen(cmd_success), 0);
      notify_workers(state);
    }
    else send(state->api.fd, cmd_fail_rcv, strlen(cmd_fail_rcv), 0);

  } else {
    struct db_msg db_msg;
    db_msg.content = calloc(strlen(buf), sizeof(char));

    char timestamp[TIME_STR_SIZE];
    get_current_time(timestamp);
    strcpy(db_msg.timestamp, timestamp);
    strcpy(db_msg.sender, state->client.username);
    strcpy(db_msg.receiver, "Null");
    strcpy(db_msg.content, buf);
    write_msg(&db_msg);
    notify_workers(state);
  }


  free(buf);
  return 0; // <-- wtf does this have to be
            // turns out it has to be zero lol TODO: document return codes of functions
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
  r = api_recv(&state->api, &msg);
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
  api_recv_free(&msg);

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

  /* TODO any additional worker state initialization */

  return 0;
}

/**
 * @brief Clean up struct worker_state when shutting down.
 * @param state        worker state
 *
 */
static void worker_state_free(
  struct worker_state *state) {
  /* TODO any additional worker state cleanup */

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
  /* TODO any additional worker initialization */
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
  /* TODO any additional worker cleanup */
  worker_state_free(&state);

  exit(success ? 0 : 1);
}
