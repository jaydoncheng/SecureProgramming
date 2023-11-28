#ifndef _SERVER_H_
#define _SERVER_H_

#define MAX_CHILDREN 16
#define TIMEOUT_SECONDS 15

struct server_child_state {
  int worker_fd;  /* server <-> worker bidirectional notification channel */
  int pending; /* notification pending yes/no */
};

struct server_state {
  int sockfd;
  struct server_child_state children[MAX_CHILDREN];
  int child_count;
};

#endif