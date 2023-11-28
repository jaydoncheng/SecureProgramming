#ifndef _UI_H_
#define _UI_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_STDIN_LEN 4095

struct ui_state {
  /* TODO add fields to store the command arguments */
  char *content;
  int content_length;
};

void ui_state_free(struct ui_state *state);
void ui_state_init(struct ui_state *state);

/* TODO add UI calls interact with user on stdin/stdout */
int ui_read_stdin(struct ui_state *state, int offset);

#endif /* defined(_UI_H_) */
