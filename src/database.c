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

int read_latest_msg(struct db_msg *msg) {
  sqlite3 *db;
  if(sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
    fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
    return -1;
  }

  const char *sel_last_msg_sql = "SELECT * FROM messages ORDER BY id DESC LIMIT 1";
  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db, sel_last_msg_sql, -1, &stmt, 0);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot prepare statement: %s\n", sqlite3_errmsg(db));
    close_db(db);
    return -1;
  }

  int error = 0;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    strncpy(msg->timestamp, (const char*)sqlite3_column_text(stmt, 1), sizeof(msg->timestamp));
    strncpy(msg->sender, (const char*)sqlite3_column_text(stmt, 2), sizeof(msg->sender));
    strncpy(msg->receiver, (const char*)sqlite3_column_text(stmt, 3), sizeof(msg->receiver));
    strncpy(msg->content, (const char*)sqlite3_column_text(stmt, 4), sizeof(msg->content));
  } else {
    fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
    error = -1;
  }

  debug_print(YEL "DB" RESET ": read_msg: %s\n", msg->content);
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
  debug_print(YEL "DB" RESET ": write_msg: %s\n", msg->content);
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

