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

  state->cont_buf_len = 128;
  state->content = calloc(state->cont_buf_len, sizeof(char));

  /* TODO initialize ui_state */
}

/**
 * @brief         Reads sizeof(state->content)-1 characters
 *                from stdin. Additional size checking
 *                is done by the server.
 * @param state   UI state to write input to
 * @returns       Returns 0 on successful read, -1 on EOF, -2, if read input size > MAX_STDIN_LEN
*/
int ui_read_stdin(struct ui_state *state, int offset) {
  if (fgets(state->content + offset, state->cont_buf_len - offset, stdin) == NULL) return -1;
  const int nbytes_read = strlen(state->content);
  if (nbytes_read > MAX_STDIN_LEN) return -2;

  if (nbytes_read == state->cont_buf_len - 1 && state->content[state->cont_buf_len - 2] != '\n') {
    state->cont_buf_len *= 2;
    state->content = realloc(state->content, state->cont_buf_len);
    ui_read_stdin(state, nbytes_read);
  }
  return 0;
}
