#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "client.h"

/**
 * @brief Connects to @hostname on port @port and returns the
 *        connection fd. Fails with -1.
 */
static int client_connect(struct client_state *state,
  const char *hostname, uint16_t port) {
  int fd;
  struct sockaddr_in addr;

  assert(state);
  assert(hostname);

  /* look up hostname */
  if (lookup_host_ipv4(hostname, &addr.sin_addr) != 0) return -1;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  /* create TCP socket */
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("error: cannot allocate server socket");
    return -1;
  }

  /* set timeout */
  struct timeval tv;
  tv.tv_sec = TIMEOUT_SECONDS;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

  /* connect to server */
  if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
    perror("error: cannot connect to server");
    close(fd);
    return -1;
  }

  /* SSL Context */
  state->ssl = SSL_new(state->ssl_ctx);
  state->ssl_ctx = SSL_CTX_new(TLS_client_method());

  /* set non-blocking*/
  if (set_nonblock(fd) < 0) return -1;

  SSL_set_fd(state->ssl, fd);
  if (ssl_block_connect(state->ssl, fd) < 0) return -1;


  return fd;
}

/**
 * @brief Read input from user and handle command,
 *        returns 0 if command is handled, -1 on /exit or
 *        ui_read_stdin fails (idk where it fails) 
**/
static int client_process_command(struct client_state *state) {
  
  assert(state);

  /* TODO read and handle user command from stdin;
   * set state->eof if there is no more input (read returns zero)
   */

  int rc = ui_read_stdin(&state->ui, 0);
  if (rc < 0) {
    printf("err %i, exiting chat...\n", rc);
    return -1;
  }

  if (strncmp(state->ui.content, "/exit", strlen("/exit")) == 0) {
    printf("Exiting chat...\n");
    return -1;
  }
  
  if (strlen(state->ui.content) == 1) {
    return 0;
  }

  int r = 0;
  r = send(state->api.fd, state->ui.content, strlen(state->ui.content), 0);
  // ^ very primitive, i think we're supposed to use api.c
  // so messages are standardized
  if (r < 0) {
    perror("send failed");
    return -1;
  }

  return 0;
}

/**
 * @brief         Handles a message coming from server (i.e, worker)
 * @param state   Initialized client state
 * @param msg     Message to handle
 */
static int execute_request(struct client_state *state, const struct api_msg *msg) {
  
  /* TODO handle request and reply to client */

  
  printf("%s", msg->content);
  return 0;
}

/**
 * @brief         Reads an incoming request from the server and handles it.
 * @param state   Initialized client state
 */
static int handle_server_request(struct client_state *state) {
  
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

/**
 * @brief register for multiple IO event, process one
 *        and return. Returns 0 if the event was processed
 *        successfully and -1 otherwise.
 *
 */
static int handle_incoming(struct client_state *state) {
  
  int fdmax, r;
  fd_set readfds;

  assert(state);

  /* TODO if we have work queued up, this might be a good time to do it */

  /* TODO ask user for input if needed */

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  FD_SET(STDIN_FILENO, &readfds);
  FD_SET(state->api.fd, &readfds);
  fdmax = state->api.fd;

  /* wait for at least one to become ready */
  r = select(fdmax+1, &readfds, NULL, NULL, NULL);
  if (r < 0) {
    if (errno == EINTR) return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  if (FD_ISSET(STDIN_FILENO, &readfds)) {
    return client_process_command(state);
  }
  /* TODO once you implement encryption you may need to call ssl_has_data
   * here due to buffering (see ssl-nonblock example)
   */
  if (FD_ISSET(state->api.fd, &readfds) && ssl_has_data(ssl)) {
    r = handle_server_request(state);
    
    return r;
  }
  return 0;
}

static int client_state_init(struct client_state *state) {
  /* clear state, invalidate file descriptors */
  memset(state, 0, sizeof(*state));

  /* initialize UI */
  ui_state_init(&state->ui);

  /* TODO any additional client state initialization */

  return 0;
}

static void client_state_free(struct client_state *state) {

  /* TODO any additional client state cleanup */
  SSL_free(state->ssl);
  SSL_CTX_free(state->ssl_ctx);
  /* cleanup API state */
  api_state_free(&state->api);

  /* cleanup UI state */
  ui_state_free(&state->ui);
}

static void usage(void) {
  printf("usage:\n");
  printf("  client host port\n");
  exit(1);
}

int main(int argc, char **argv) {
  int fd;
  uint16_t port;
  struct client_state state;

  /* check arguments */
  if (argc != 3) usage();
  if (parse_port(argv[2], &port) != 0) usage();

  /* preparations */
  client_state_init(&state);

  /* connect to server */
  fd = client_connect(&state, argv[1], port);
  if (fd < 0) return 1;

  /* initialize API */
  api_state_init(&state.api, fd);

  /* TODO any additional client initialization */
  printf("to register -> /register <username> <password>\nto log in -> /login <username> <password>\n");
  /* client things */
  while (!state.eof && handle_incoming(&state) == 0);

  /* clean up */
  /* TODO any additional client cleanup */
  client_state_free(&state);
  close(fd);

  return 0;
}
