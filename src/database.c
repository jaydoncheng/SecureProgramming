#include "util.h"
#include "database.h"

int close_db(sqlite3 *db) {
  sqlite3_close(db);
  return 0;
}

int init_db() {
  sqlite3 *db;
  if(sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
    return -1;
  }
  const char *msgTable = "CREATE TABLE IF NOT EXISTS messages ("
                         "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                         "timestamp TEXT NOT NULL,"
                         "sender TEXT NOT NULL,"
                         "receiver TEXT NOT NULL,"
                         "content TEXT NOT NULL);";

  int rc = sqlite3_exec(db, msgTable, 0, 0, 0);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot create msg table: %s\n", sqlite3_errmsg(db));
    close_db(db);
    return -1;
  }

  const char *userTable = "CREATE TABLE IF NOT EXISTS users ("
                          "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                          "username TEXT NOT NULL,"
                          "password TEXT NOT NULL);";

  rc = sqlite3_exec(db, userTable, 0, 0, 0);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot create user table: %s\n", sqlite3_errmsg(db));
    close_db(db);
    return -1;
  }
  close_db(db);
  return 0;
}

int prepare_statement(sqlite3 *db, char *sql, sqlite3_stmt **stmt) {
  int rc = sqlite3_prepare_v2(db, sql, -1, stmt, 0);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot prepare statement: %s\n", sqlite3_errmsg(db));
    close_db(db);
    return -1;
  }
  return rc;
}

void db_to_msg(struct db_msg *msg, sqlite3_stmt *stmt) {
  strncpy(msg->timestamp, (const char*)sqlite3_column_text(stmt, 1), sizeof(msg->timestamp));
  strncpy(msg->sender, (const char*)sqlite3_column_text(stmt, 2), sizeof(msg->sender));
  strncpy(msg->receiver, (const char*)sqlite3_column_text(stmt, 3), sizeof(msg->receiver));
  msg->content = calloc(strlen((const char *)sqlite3_column_text(stmt, 4)), sizeof(char));
  strcpy(msg->content, (const char*)sqlite3_column_text(stmt, 4));
}

int read_latest_msg(struct db_msg *msg) {
  sqlite3 *db;
  if(sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
    return -1;
  }

  sqlite3_stmt *stmt = NULL;
  prepare_statement(db, "SELECT * FROM messages ORDER BY id DESC LIMIT 1", &stmt);

  int error = 0;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    db_to_msg(msg, stmt);
  } else {
    fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
    error = -1;
  }

  
  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return error;
}

int write_msg(struct db_msg *msg) {
  sqlite3 *db;
  if(sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
    return -1;
  }

  const char *insert_message_sql = "INSERT INTO messages (timestamp, sender, receiver, content) VALUES (?, ?, ?, ?);";
  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db, insert_message_sql, -1, &stmt, 0);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot prepare statement: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    //return 1;
  }
  
  sqlite3_bind_text(stmt, 1, msg->timestamp, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, msg->sender, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 3, msg->receiver, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 4, msg->content, -1, SQLITE_STATIC);
  rc = sqlite3_step(stmt);

  if (rc != SQLITE_DONE) {
    fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
  }
  
  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return 0;
}

void format_db_msg(struct db_msg *msg, char *buf) {
  buf = calloc(DB_MSG_SIZE + strlen(msg->content) + 3, sizeof(char));
  sprintf(buf, "%s %s: %s", msg->timestamp, msg->sender, msg->content);
}
