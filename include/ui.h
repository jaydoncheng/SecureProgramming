#ifndef _UI_H_
#define _UI_H_

#include <stdio.h>
#include <string.h>

struct ui_state {
  /* TODO add fields to store the command arguments */
  char buf[256];
};

void ui_state_free(struct ui_state *state);
void ui_state_init(struct ui_state *state);

/* TODO add UI calls interact with user on stdin/stdout */
int ui_read_stdin(struct ui_state *state);

#endif /* defined(_UI_H_) */
