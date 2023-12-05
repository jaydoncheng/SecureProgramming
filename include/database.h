#ifndef _DATABASE_H
#define _DATABASE_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sqlite3.h"

#define DB_FILE "chat.db"

/**
 * Needs to be allocated to fit a 
 * variable content size.
 */
struct db_msg {
    char timestamp[TIME_STR_SIZE];
    char sender[32];
    char receiver[32];
    char *content;
};

#define DB_MSG_SIZE sizeof(struct db_msg) 

int open_db(sqlite3 **db);
int init_db();
int close_db(sqlite3 *db);

int prepare_statement(sqlite3 *db, char *sql, sqlite3_stmt **stmt);
void db_to_msg(struct db_msg *msg, sqlite3_stmt *stmt);
int read_latest_msg(struct db_msg *msg);
int write_msg(struct db_msg *msg);
int user_exists(sqlite3 *db, char username[32]);
int user_check(char username[32]);

void format_db_msg(struct db_msg *msg, char *buf);

int register_user(char username[32], char password[64]); 
int login_user(char username[32], char password[64]); 
int handle_prv_msg(char username[32], char rcv_username[32], char messageContent[256]);
int handle_msg(char *sender, char *receiver, char *msgContent);
int handle_pub_msg(char *username, char *msgContent);
#endif /* defined(_DATABASE_H_) */
