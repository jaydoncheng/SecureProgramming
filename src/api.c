#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "util.h"
#include "api.h"
#include "ssl-nonblock.h"

/**
 * @brief         Receive the next message from the sender and stored in msg.
 *                A partial recv is possible if a newline char isn't found,
 *                recv will timeout after TIMEOUT_SECONDS (server and client).
 *                
 * @return        Returns 1 on new message, 0 in case socket was closed,
 *                or -1 in case of error.
 */
int api_recv(SSL *ssl, struct api_state *state, struct api_msg *msg) {
  assert(msg);
  assert(state);

  msg->cont_buf_len = DEFAULT_MSG_LEN;
  msg->content = calloc(DEFAULT_MSG_LEN, sizeof(char));


  ssize_t total = 0; /* also an offset for where to continue writing to */
  ssize_t count = 0;
  while ((count = SSL_read(ssl, msg->content + total, msg->cont_buf_len - total)) > 0) { 
    if (count < 0) {
      fprintf(stderr, "error: recv failed: %s\n", strerror(errno));
      return -1;
    }

    total += count;
    int r;
    r = ssl_block_if_needed(ssl, state->fd, r);
    if (r < 0) return -1;
    if (r == 0) break; /* might have to use this if below line doesn't work */

    if (strchr(msg->content, '\n')) break; /* comment this to test timeouts */
    if (msg->cont_buf_len - total == 0) {
      msg->cont_buf_len *= 2;
      msg->content = realloc(msg->content, msg->cont_buf_len * sizeof(char));
    }
    
  };
  if (total == 0) return 0;
  return 1;
}

/**
 * @brief         Clean up information stored in msg
 */
void api_msg_free(struct api_msg *msg) {

  assert(msg);

  free(msg->content);
}

int api_send(SSL *ssl, int fd, const void *buf, int len) {
  /* Code taken from ssl_block_write in the provided examples */
  const char *p = buf, *pend = p + len;
  int r;

  while (p < pend) {
    r = SSL_write(ssl, p, pend - p);
    if (r > 0) {
      p += r;
      break;
    }

    r = ssl_block_if_needed(ssl, fd, r);
    if (r < 0) return -1;
    if (r == 0) break;
  }
  return 0;
}


/**
 * @brief         Frees api_state context
 */
void api_state_free(struct api_state *state) {

  assert(state);

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

}
