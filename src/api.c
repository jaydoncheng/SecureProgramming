#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

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
  msg->bufsize = STD_MSG_LEN;
  msg->buf = calloc(STD_MSG_LEN, sizeof(char));

  assert(state);
  assert(msg);

  /* TODO receive a message and store information in *msg */
  ssize_t total = 0;
  ssize_t count = 0;
  while ((count = recv(state->fd, msg->buf + total, msg->bufsize - total, 0)) > 0) {
    if (count < 0) return -1;
    total += count;
    
    if (strchr(msg->buf, '\n')) break;
    if (msg->bufsize - total == 0) { 
      msg->bufsize *= 2;
      msg->buf = realloc(msg->buf, msg->bufsize);
    }
  };
  
  if (total == 0) return 0;
  return 1;
}

/**
 * @brief         Clean up information stored in @msg
 * @param msg     Information about message to be cleaned up
 */
void api_recv_free(struct api_msg *msg) {

  assert(msg);

  free(msg->buf);
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
