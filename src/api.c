#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

#include "util.h"
#include "api.h"

/**
 * @brief         Receive the next message from the sender and stored in @msg
 * @param state   Initialized API state
 * @param msg     Information about message is stored here
 * @return        Returns 1 on new message, 0 in case socket was closed,
 *                or -1 in case of error.
 */
int api_recv(struct api_state *state, struct api_msg *msg) {

  assert(state);
  assert(msg);

  /* TODO receive a message and store information in *msg */
  ssize_t r;

  r = read(state->fd, msg->buf, sizeof(msg->buf));

  if (r < 0) {
    debug_print("api_recv read failed\n");
    return -1;
  }

  if (r == 0) {
    debug_print("api_recv nothing to read\n");
    return 0;
  }

  sqlite3 *db;
  int rc = sqlite3_open("chat.db", &db);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return 1;
  }
  else printf("db opened successfuly\n");

  const char *insert_message_sql = "INSERT INTO messages (sender, receiver, content) VALUES (?, ?, ?);";

sqlite3_stmt *stmt;

rc = sqlite3_prepare_v2(db, insert_message_sql, -1, &stmt, 0);

if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot prepare statement: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    //return 1;
}

const char *sender = "user1";
const char *receiver = "user2";

sqlite3_bind_text(stmt, 1, sender, -1, SQLITE_STATIC);
sqlite3_bind_text(stmt, 2, receiver, -1, SQLITE_STATIC);
sqlite3_bind_text(stmt, 3, msg->buf, -1, SQLITE_STATIC);

rc = sqlite3_step(stmt);

if (rc != SQLITE_DONE) {
    fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
}

sqlite3_finalize(stmt);

sqlite3_close(db);

  return 1;
}

/**
 * @brief         Clean up information stored in @msg
 * @param msg     Information about message to be cleaned up
 */
void api_recv_free(struct api_msg *msg) {

  assert(msg);

  /* TODO clean up state allocated for msg */
}

/**
 * @brief         Frees api_state context
 * @param state   Initialized API state to be cleaned up
 */
void api_state_free(struct api_state *state) {

  assert(state);

  /* TODO clean up API state */
}

/**
 * @brief         Initializes api_state context
 * @param state   API state to be initialized
 * @param fd      File descriptor of connection socket
 */
void api_state_init(struct api_state *state, int fd) {

  assert(state);

  /* initialize to zero */
  memset(state, 0, sizeof(*state));

  /* store connection socket */
  state->fd = fd;

  /* TODO initialize API state */
}
