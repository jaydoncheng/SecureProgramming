#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "util.h"
#include "api.h"

/**
 * @brief         Receive the next message from the sender and stored in msg.
 *                A partial recv is possible if a newline char isn't found,
 *                recv will timeout after TIMEOUT_SECONDS (server and client).
 *                
 * @return        Returns 1 on new message, 0 in case socket was closed,
 *                or -1 in case of error.
 */
int api_recv(struct api_state *state, struct api_msg *msg) {
  msg->content_size = DEFAULT_MSG_LEN;
  msg->content = calloc(DEFAULT_MSG_LEN, sizeof(char));

  assert(state);
  assert(msg);

  ssize_t total = 0; /* also an offset for where to continue writing to */
  ssize_t count = 0;
  while ((count = recv(state->fd, msg->content + total, msg->content_size - total, 0)) > 0) {
    if (count < 0) {
      perror("error: recv failed/timed out");
      return -1;
    }

    total += count;
    
    if (strchr(msg->content, '\n')) break; /* comment this to test timeouts */
    if (msg->content_size - total == 0) {
      msg->content_size *= 2;
      msg->content = realloc(msg->content, msg->content_size * sizeof(char));
    }
  };
 
  if (total == 0) return 0;
  return 1;
}

/**
 * @brief         Clean up information stored in msg
 */
void api_recv_free(struct api_msg *msg) {

  assert(msg);

  free(msg->content);
  /* TODO clean up state allocated for msg */
}

/**
 * @brief         Frees api_state context
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
