#include <assert.h>

#include "ui.h"

/**
 * @brief         Frees ui_state context
 * @param state   Initialized UI state to be cleaned up
 */
void ui_state_free(struct ui_state *state) {

  assert(state);

  free(state->content);
  /* TODO free ui_state */
}

/**
 * @brief         Initializes ui_state context
 * @param state   UI state to be initialized
 */
void ui_state_init(struct ui_state *state) {

  assert(state);
  memset(state, 0, sizeof(*state));

  state->content_length = 128;
  state->content = calloc(state->content_length, sizeof(char));

  /* TODO initialize ui_state */
}

/**
 * @brief         Reads sizeof(state->content)-1 characters
 *                from stdin. Additional size checking
 *                is done by the server.
 * @param state   UI state to write input to
 * @returns       Returns 0 on successful read, -1 if read input size > MAX_STDIN_LEN
*/
int ui_read_stdin(struct ui_state *state, int offset) {
  fgets(state->content + offset, state->content_length - offset, stdin);
  const int nbytes_read = strlen(state->content);
  if (nbytes_read > MAX_STDIN_LEN) return -1;

  if (nbytes_read == state->content_length - 1 && state->content[state->content_length - 2] != '\n') {
    state->content_length *= 2;
    state->content = realloc(state->content, state->content_length);
    ui_read_stdin(state, nbytes_read);
  }
  return 0;
}
