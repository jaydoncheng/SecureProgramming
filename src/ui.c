#include <assert.h>

#include "ui.h"

/**
 * @brief         Frees ui_state context
 * @param state   Initialized UI state to be cleaned up
 */
void ui_state_free(struct ui_state *state) {

  assert(state);

  free(state->buf);
  /* TODO free ui_state */
}

/**
 * @brief         Initializes ui_state context
 * @param state   UI state to be initialized
 */
void ui_state_init(struct ui_state *state) {

  assert(state);
  memset(state, 0, sizeof(*state));

  state->bufsize = 128;
  state->buf = calloc(state->bufsize, sizeof(char));

  /* TODO initialize ui_state */
}

/**
 * @brief         Reads sizeof(state->buf)-1 characters
 *                from stdin. Additional size checking
 *                is done by the server.
 * @param state   UI state to write input to
 * @returns       Returns 0 on successful read, -1 if read input size > MAX_CLIENT_INPUT
*/
int ui_read_stdin(struct ui_state *state, int offset) {
  fgets(state->buf + offset, state->bufsize - offset, stdin);
  if (strlen(state->buf) > MAX_STDIN_LEN);

  if (strlen(state->buf) == state->bufsize - 1 && state->buf[state->bufsize - 2] != '\n') {
    state->bufsize *= 2;
    state->buf = realloc(state->buf, state->bufsize);
    ui_read_stdin(state, strlen(state->buf));
  }
  return 0;
}
