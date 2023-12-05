.PHONY: all clean

CFLAGS=-g -Wall -Werror -UDEBUG -I$(INC_DIR)
LDLIBS=-lsqlite3 -lcrypto -lssl

OBJ_DIR=obj
SRC_DIR=src
INC_DIR=include
SERVERKEY_DIR = serverkeys
CLIENTKEY_DIR = clientkeys
TTP_DIR = ttpkeys

CLIENT_INC=api.h ui.h util.h ssl-nonblock.h
CLIENT_OBJS=client.o api.o util.o ui.o ssl-nonblock.o

SERVER_INC=util.h database.h ssl-nonblock.h
SERVER_OBJS=server.o api.o util.o worker.o database.o ssl-nonblock.o

all: mkdirs client server client_keys server_keys

# compile any object matching .o with the relevant .c and .h files
# the -Iinclude flag in $(CFLAGS) makes gcc search include/ for the relevant .h files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	gcc $(CFLAGS) -c $< -o $@ $(LDLIBS)

# client.o and server.o require extra headers (see the *_INC variables)
$(OBJ_DIR)/client.o: $(SRC_DIR)/client.c $(addprefix $(INC_DIR)/, $(CLIENT_INC))
$(OBJ_DIR)/server.o: $(SRC_DIR)/server.c $(addprefix $(INC_DIR)/, $(SERVER_INC))

client: $(addprefix $(OBJ_DIR)/, $(CLIENT_OBJS))
	gcc $^ -o client $(LDLIBS)

client_keys:
	python3 gen_keys.py $(CLIENTKEY_DIR)

server_keys:
	python3 gen_keys.py $(SERVERKEY_DIR)

server: $(addprefix $(OBJ_DIR)/, $(SERVER_OBJS))
	gcc $^ -o server $(LDLIBS)

mkdirs:
	mkdir -p $(OBJ_DIR) $(SERVERKEY_DIR) $(CLIENTKEY_DIR) $(TTP_DIR)

clean:
	rm -rf server client $(OBJ_DIR) chat.db $(SERVERKEY_DIR) $(CLIENTKEY_DIR)