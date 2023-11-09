# Secure Programming 2023 - Webchat

## Documentation stuff
will add later

## First assignment:
- [ ] Handling incoming connections (B.3 in PDF)
- [x] Exiting the program using `/exit` → needs to handle commands, for now we can probably just check for `input == “/exit”`, later we’ll need to parse all messages according to (F14)
- [ ] Exiting the program CTRL+D (end-of-file) (I guess both client and server)
- [ ] Public messages (F6) → message needs to be sent from client to server, which the server then sends to all clients
- [ ] Retaining old messages (F5, N1) → need to store messages
README.md


### Functional requirements (F)
- [ ] 1. The user can register a new account. To do so, they will have to supply a username and a password.
You are allowed (but not required) to set a maximum length for the username and/or the password, as long as it is no less than 8 characters.
- [ ] 2. The application prohibits registration of a user with a previously registered username.
- [ ] 3. The user can login. It is only possible to login to an account if one knows the password supplied at registration time.
- [ ] 4. The user can exit. This logs out from the server and terminates the client program.
- [ ] 5. When the client starts, it displays all public messages previously sent by anyone, and all private messages received and sent by the current user, in chronological order from old to new.
- [ ] 6. The user can send a public message to all users.
- [ ] 7 .The user can send a private message to a specific user.
- [ ] 8. You are allowed (but not required) to set a maximum length for messages, as long as it is no less than 140 characters.
- [ ] 9. Each message is shown together with a timestamp, the user who sent it, and for private messages also the recipient.
- [ ] 10. The clients only show (1) public messages and (2) private messages of which the logged in user is either the sender or the recipient.
- [ ] 11. Each message will be shown to its recipient(s) immediately (or at least, as immediate as network latency will allow).
- [ ] 12. The client provides a list of logged in users on request.
- [ ] 13. The server should allow at least 10 simultaneous connections.
- [ ] 14. Each message is parsed according to `[WHITESPACE] command [WHITESPACE] NEWLINE`

### Non-functional requirements (N)
- [ ] 1. The server stores all permanent state in a SQLite database named chat.db, located within the application’s root directory. (Users, messages)
- [ ] 2. Servers and clients should store cryptographic keys in their respective directories (serverkeys, clientkeys)
- [ ] 3. The programs may only access their own cryptographic key directories and the trusted third party keys (ttpkeys) directory.
- [ ] 4. Besides the database and key directories, nothing else may be stored on disk.
- [ ] 5. Restarting the program should not cause any data loss, only the need to re-establish connections
- [ ] 6. Clients only connect to the server, not other clients.
