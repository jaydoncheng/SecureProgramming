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

struct worker_state {
  struct api_state api;
  int eof;
  int server_fd;  /* server <-> worker bidirectional notification channel */
  int server_eof;
  /* TODO worker state variables go here */
};

/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state) {
  /* TODO implement the function */
  debug_print(RED "WORKER" RESET ": handle_s2w_notification\n");
  struct db_msg db_msg;
  read_latest_msg(&db_msg);
  char buf[512];

  snprintf(buf, sizeof(buf), "%s %s: %s", db_msg.timestamp, db_msg.sender, db_msg.content);
  debug_print(RED "WORKER" RESET ": strlen(buf)=%li\n", strlen(buf));
  int r = send(state->api.fd, buf, strlen(buf), 0);
  debug_print(RED "WORKER" RESET ": sent %i bytes\n", r);
  return 0;
}

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
/* TODO call this function to notify other workers through server */
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

/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 */
static int execute_request(
  struct worker_state *state,
  const struct api_msg *msg) {

  debug_print(RED "WORKER" RESET ": execute_request\n");
  
  /* TODO handle request and reply to client */

  char buf[256];
  int l = 0;
  while (isprint(msg->buf[l])) {
    buf[l] = msg->buf[l];
    l++;
  }
  buf[l] = '\n';
  buf[l+1] = '\0';

  if (strlen(buf) == 1) return 0;

  char timestamp[TIME_STR_SIZE];
  get_current_time(timestamp);
  struct db_msg db_msg;
  strcpy(db_msg.timestamp, timestamp);
  strcpy(db_msg.sender, "User");
  strcpy(db_msg.receiver, "Null");
  strcpy(db_msg.content, buf);
  write_msg(&db_msg);

  notify_workers(state);
  debug_print(RED "WORKER" RESET ": notified workers\n");

  return 0; // <-- wtf does this have to be
            // turns out it has to be zero lol TODO: document return codes of functions
}

/**
 * @brief         Reads an incoming request from the client and handles it.
 * @param state   Initialized worker state
 */
static int handle_client_request(struct worker_state *state) {
  debug_print(RED "WORKER" RESET ": handle_client_request\n");
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

  debug_print(RED "WORKER" RESET ": received msg: %s", msg.buf);
  /* execute request */
  if (execute_request(state, &msg) != 0) {
    success = 0;
  }

  /* clean up state associated with the message */
  api_recv_free(&msg);

  return success ? 0 : -1;
}

static int handle_s2w_read(struct worker_state *state) {
  debug_print(RED "WORKER" RESET ": handle_s2w_read\n");
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
  debug_print(RED "WORKER" RESET ": handle_incoming\n");
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

int send_chat_history(struct worker_state *state) {
  debug_print(RED "WORKER" RESET ": send_chat_history\n");
  sqlite3 *db;
  char buf[512];
  struct db_msg msg;
  sqlite3_stmt *stmt;
  int error = 0;

  fd_set writefds;
  FD_ZERO(&writefds);
  FD_SET(state->api.fd, &writefds);
  int fdmax = state->api.fd;

  if(sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
    return -1;
  }

  const char *sel_last_msg_sql = "SELECT * FROM messages ORDER BY id ASC";
  int rc = sqlite3_prepare_v2(db, sel_last_msg_sql, -1, &stmt, 0);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot prepare statement: %s\n", sqlite3_errmsg(db));
    close_db(db);
    return -1;
  }

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    strncpy(msg.timestamp, (const char*)sqlite3_column_text(stmt, 1), sizeof(msg.timestamp));
    strncpy(msg.sender, (const char*)sqlite3_column_text(stmt, 2), sizeof(msg.sender));
    strncpy(msg.receiver, (const char*)sqlite3_column_text(stmt, 3), sizeof(msg.receiver));
    strncpy(msg.content, (const char*)sqlite3_column_text(stmt, 4), sizeof(msg.content));
    snprintf(buf, sizeof(buf), "%s %s: %s", msg.timestamp, msg.sender, msg.content);
    debug_print(RED "WORKER" RESET ": strlen(buf)=%li\n", strlen(buf));

    int r = select(fdmax+1, NULL, &writefds, NULL, NULL);
    if (r < 0) {
      perror("dude im sot ired");
      return -1;
    }
    if (FD_ISSET(state->api.fd, &writefds)) {
      r = send(state->api.fd, buf, strlen(buf), 0);
    }
    debug_print(RED "WORKER" RESET ": sent %i bytes\n", r);
    debug_print(YEL "DB" RESET ": send_chat_history: %s\n", msg.content);
  }


  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return error;
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
  send_chat_history(&state);
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
