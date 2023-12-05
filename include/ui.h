#ifndef _UI_H_
#define _UI_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_STDIN_LEN 4095

struct ui_state {
  char *content;
  int cont_buf_len;
};

void ui_state_free(struct ui_state *state);
void ui_state_init(struct ui_state *state);

int ui_read_stdin(struct ui_state *state, int offset);

#endif /* defined(_UI_H_) */
