# Secure Programming 2023 - Webchat


## Commands:
1. User Registration and Login Commands:
/register <user> <password>: Register with a chosen username and securely hashed password.
/login <user> <password>: Log in by entering your username and password, with secure hash comparison.

2. Display Users Command:
/users: View the list of currently registered users.

3. Exit Command:
/exit: Gracefully exit the chat application, ensuring a clean disconnection.

4. Private Message Command: **Not working**
@user <private message>: Send a private, securely encrypted message to the specified user.
**A memory leak (which we could not find in time) is causing private messages to crash the server,
which we think is from a loose database pointer (or some other pointer) due to invalid logic**

## Database Structure:
File: chat.db

Tables:

messages:

id: Message ID
timestamp: Timestamp of the message
sender: Sender's username
receiver: Receiver's username (set to "Null" for public messages)
content: Message content
users:

id: User ID
username: User's chosen username
password: Hashed password
salt: Salt used in password hashing
User Registration:

Prevent registration with the username "Null" to avoid conflicts with public message handling.
Database Functions (in database.c)
Generic Database Functions:

open_db: Open the database file.
init_db: Initialize the database structure and tables.
close_db: Close the database connection.
Reading and Writing Functions:

read_latest_msg: Retrieve the latest message from the database.
write_msg: Write a new message to the database.
print_users: Display the list of registered users.

## Security Design
### Messages between client and server
* Authentication messages
    * The client and server use a TLS handshake to establish a secure connection. The client sends a request to the server with a client random, which the server replies to with its SSL certificate and its server random.
    * After confirming the certificate, the client and server generate the premaster secret separately (using the Diffie-Hellman algorithm) and calculate the session keys using the premaster secret.
* Command request/reply from client <-> server
    * Every command request and reply uses the session keys obtained from authentication to securely transmit data.

### Key related information
**Key Pair Generation:**
Users generate a pair of cryptographic keys, public and private keys.
Public keys are shared openly, while private keys are kept secret. 

**Key Exchange:**
Users exchange public keys securely. This step happens via a trusted server.
Key distribution center (KDC) is involved in this process which shares symmetric keys with all others. 

**Session Key Generation:**
When two users engage in a conversation, they establish a secure session and generate a unique session key. The generation of the session key should be done securely and therefore that involves the use of Diffie-Hellman key exchange protocol.

**Message Encryption:**
Messages are encrypted with the session key before sending and decrypted on the recipient’s end. This ensures that the content of the messages remains confidential during transmission.

**Perfect Forward Secrecy:**
A new session key is generated for each session, providing perfect forward secrecy.
Even if an attacker compromises a user’s key, they can't decrypt past messages due to the unique session keys for each conversation.

**Key Management (Using KDC - OpenSSL):**
A trusted third party (TTP) acts as a Key Distribution Center (KDC). The KDC shares symmetric keys with all users. The KDC verifies the identities of key owners, ensuring the integrity of the key exchange process. The TTP/KDC should receive as little private information as possible to maintain user privacy.

**Identity Verification:**
Self-signed certificates are used to prove the identities of users.
This adds an additional layer of security by ensuring that the public key received during key exchange indeed belongs to the claimed user. Server is responsible for this part as SSL typically does not authenticate the client. 

**Symmetric Encryption Key Establishment:**
Diffie-Hellman key exchange is used for establishing symmetric encryption keys securely.
This protocol allows two parties to generate a shared secret key over an insecure channel.


### Security properties
1. Mallory cannot get information about private messages for which they are not either the sender or the intended recipient.
2. Mallory cannot send messages on behalf of another user. 
3. Mallory cannot modify messages sent by other users.
4. Mallory cannot find out users’ passwords, private keys, or private messages. 

Firstly, confidentiality is maintained through the use of session keys established via the TLS handshake, employing the Diffie-Hellman key exchange. This ensures that private messages are encrypted and only accessible to the intended recipients, preventing unauthorized access by Mallory. [1]  
Authentication plays a crucial role, thwarting Mallory's attempts to send messages on behalf of other users. The TLS handshake, involving self-signed certificate verification and key exchange, ensures that only authenticated users can participate in the communication, safeguarding against unauthorized impersonation. [2]  
Ensuring message integrity is another vital aspect of our design. While private messages are encrypted, any tampering attempts by Mallory would result in corrupted messages upon decryption, alerting the sender and recipient to potential malicious activities and logging them out to generate a new session key. [3]  
Sensitive information, including passwords and private keys, is well-protected. Passwords are securely stored using salted hash techniques, making it computationally challenging for Mallory to uncover them. Private keys, crucial for decryption, are never shared, and private messages remain confidential through encryption, shielding them from prying eyes. [4]

Perfect forward secrecy is achieved by generating a new session key for each session using Diffie-Hellman key exchange. Even if Mallory were to compromise a user's key, past messages remain secure due to the unique session keys for each conversation.
Lastly, identity verification is enhanced by the use of self-signed certificates during the key exchange process. This ensures that the public key received indeed belongs to the claimed user, adding an extra layer of security against unauthorized participation in the communication.
In essence, our design not only prioritizes the confidentiality, authentication, and integrity of messages but also fortifies the protection of sensitive user information, maintains perfect forward secrecy, and enhances identity verification to create a robust and secure chat application.

## Cryptography
**Password hashing:**
1. Database Storage
Data Stored: In the database (chat.db), user information is stored in the 'users' table, which includes the fields:
id: User ID
username: User's chosen username
password: Hashed password
salt: Salt used in the hashing process
2. User Registration (register_user() in database.c)
Function Invocation: When a user registers, the register_user() function in 'database.c' is called.

Generate Salt: The first step is to generate a random salt. The generate_salt() function is invoked for this purpose, creating a unique random string.

Hash Generation: The generated salt, along with the user's chosen password, is passed to the generate_hash() function. This function applies cryptographic functions to create a hashed password. The hashed password, along with the username and salt, is then stored in the database.

3. User Login (login_user() in database.c)
Function Invocation: When a user attempts to log in, the login_user() function in 'database.c' is called.

Retrieve Salt: The salt associated with the user is retrieved from the database based on the provided username.

Hash Generation: The generate_hash() function is again invoked, using the retrieved salt and the password entered during login. This process generates a hash from the entered password.

Comparison: The generated hash is compared with the stored hash in the database. If the two hashes match, the user is authorized, indicating a successful login. This comparison ensures that the user has entered the correct password without exposing the actual password or salt.

4. Confidentiality Measures
Protection in Database Leak Scenario: In the unfortunate event of a database leak, the confidentiality of users' passwords remains intact. The leaked information would consist of hashed passwords and associated salts, making it computationally challenging for an attacker to decipher the original passwords.

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


