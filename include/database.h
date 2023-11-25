#ifndef _DATABASE_H
#define _DATABASE_H_

#include <stdio.h>
#include <string.h>
#include "sqlite3.h"

#define DB_FILE "chat.db"


struct db_msg {
    char timestamp[TIME_STR_SIZE];
    char sender[32];
    char receiver[32];
    char content[256];
};

int open_db(sqlite3 *db);
int init_db();
int close_db(sqlite3 *db);

int prepare_statement(sqlite3 *db, char *sql, sqlite3_stmt **stmt);
void db_to_msg(struct db_msg *msg, sqlite3_stmt *stmt);
int read_latest_msg(struct db_msg *msg);
int write_msg(struct db_msg *msg);

#endif /* defined(_DATABASE_H_) */
