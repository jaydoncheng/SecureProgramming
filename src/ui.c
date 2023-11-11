#include <assert.h>

#include "ui.h"

/**
 * @brief         Frees ui_state context
 * @param state   Initialized UI state to be cleaned up
 */
void ui_state_free(struct ui_state *state) {

  assert(state);

  /* TODO free ui_state */
}

/**
 * @brief         Initializes ui_state context
 * @param state   UI state to be initialized
 */
void ui_state_init(struct ui_state *state) {

  assert(state);
  memset(state, 0, sizeof(*state));

  /* TODO initialize ui_state */
  printf("sizeof(state->buf): %li\n", sizeof(state->buf));
}

int ui_read_stdin(struct ui_state *state) {
  if (fgets(state->buf, sizeof(state->buf), stdin) != NULL) {
    return 0;
  }

  return 1;
}
