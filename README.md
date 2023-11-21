# Secure Programming 2023 - Webchat

## Protocols
The protocols follow the provided framework:
- server.c handles the initial connection with the client and assigns them to a worker, the server also handles communication between workers.
- worker.c handles communication between it and its client.
- client.c gives the user an interface with the server.

**Connecting**:
1. Server is listening for new connections, as well as worker notifications (`handle_incoming`)
2. Client attempts to connect
3. Server catches this and calls `handle_connection`, the server will fully accept the connection if there is space for a new worker
    - If there's space, the server will fork and enter into `worker_start` with the FD of the client
4. Worker sends all previous messages [send_chat_history](src/worker.c#L229) and enters a loop listening for incoming requests in [handle_incoming](src/worker.c)

**Client messages**:
1. Client sends a message
2. Worker catches this in `handle_client_request`, which reads the message and forwards it to `execute_request`
3. The message is sanitized and written to the database
4. Worker calls `notify_workers`, which sends an empty char to Server
5. Server catches the empty notification in [handle_w2s_read](src/server.c#L31) and notifies the other workers through [handle_s2w_write](src/server.c#L223)
6. Worker handles the empty notification in [handle_s2w_read](src/worker.c#L134) and [handle_s2w_notification](src/worker.c#L27)
7. Worker reads the latest message from the database and sends it to Client

## Design for the use of cryptography

**Message Exchange**:

**Key Distribution**:

**Addressing Security Requirements**: 



## FIXMEs
- send/recv buffer sizes aren't handled properly on both server and client
    - [worker.c handle_s2w_notification](src/worker.c#L36) uses a 512 byte size array
    - [api.c api_recv](src/api.c#L24) handles >256 character strings properly for the client in [handle_server_request](src/client.c#L111) but not in [handle_client_request->execute_request](src/worker.c#L76)
    - [client.c client_process_command](src/client.c#L76) doesn't account for user input buffer

- Server clean-up is never reached when terminating with ctrl+c [server.c main](src/server.c#L387)
