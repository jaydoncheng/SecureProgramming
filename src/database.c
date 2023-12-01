#include "util.h"
#include "database.h"

int open_db(sqlite3 **db) {
  if (sqlite3_open(DB_FILE, db) != SQLITE_OK) {
    fprintf(stderr, "error opening database: %s\n", sqlite3_errmsg(*db));
    return -1;
  }
  return 0;
}

int close_db(sqlite3 *db) {
  sqlite3_close(db);
  return 0;
}

int init_db() {
  sqlite3 *db = NULL;
  if (open_db(&db) != 0) return -1;

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

/**
 * @brief   Prepares a statement for later use through `sqlite3_step`.
 *          Handle error by exiting caller function after failed `prepare_statement`.
 * @returns `0` on success, `-1` on error (will close database)
 */
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
  sqlite3 *db = NULL;
  if (open_db(&db) != 0) return -1;

  sqlite3_stmt *stmt = NULL;
  int rc = prepare_statement(db, "SELECT * FROM messages ORDER BY id DESC LIMIT 1", &stmt);
  if (rc == -1) return -1;

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
  sqlite3 *db = NULL;
  if (open_db(&db) != 0) return -1;

  char *insert_message_sql = "INSERT INTO messages (timestamp, sender, receiver, content) VALUES (?, ?, ?, ?);";
  sqlite3_stmt *stmt = NULL;
  int rc = prepare_statement(db, insert_message_sql, &stmt);
 
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

/**
 * @brief   Check whether a user exists already.
 *          \!!Does not finalize statement or close database\!!
 * @returns 0 if user does not exist, 1 if user exists, -1 on error
*/
int user_exists(sqlite3 *db, char username[32]) {
  sqlite3_stmt *stmt = NULL;
  int rc = prepare_statement(db, "SELECT * FROM users WHERE username=(?)", &stmt);
  if (rc == -1) return -1;

  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  if (rc == SQLITE_ROW) {
    close_db(db);
    return 1;
  }
  
  return 0;
}

int login_user(char username[32], char password[64]) {
  int rc;
  sqlite3 *db = NULL;
  if (open_db(&db) != 0) {
    return -1;
  }
  if (!user_exists(db, username)) return 1;
  if (open_db(&db) != 0) {
    return -1;
  }
  sqlite3_stmt *stmt = NULL;
  rc = prepare_statement(db, "SELECT password FROM users WHERE username=(?)", &stmt);
  if (rc == -1) return -1;

  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
  rc = sqlite3_step(stmt);

  if (rc == SQLITE_ROW) {
    // If a row is found, compare the stored password with the provided password
    const char *stored_password = (const char *)sqlite3_column_text(stmt, 0);

    if (strcmp(stored_password, password) == 0) {
      // Passwords match
      printf("Login successful\n");
    } else {
      // Password does not match
      printf("Incorrect password\n");
    }
  } else if (rc == SQLITE_DONE) {
    // the username was not found
    fprintf(stderr, "User not found\n");
  } else {
    // An error occurred during execution
    fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
  }

  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return 0;
}

int register_user(char username[32], char password[64]) {
  int rc;
  sqlite3 *db = NULL;
  if (open_db(&db) != 0) {
    return -1;
  }
  if (user_exists(db, username)) return 1;

  sqlite3_stmt *stmt = NULL;
  rc = prepare_statement(db, "INSERT INTO users (username, password) VALUES (?, ?)", &stmt);
  if (rc == -1) return -1;

  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, password, -1, SQLITE_STATIC);
  rc = sqlite3_step(stmt);
  
  if (rc != SQLITE_DONE) {
    fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
  }

  sqlite3_finalize(stmt);
  sqlite3_close(db);
  return 0;
}