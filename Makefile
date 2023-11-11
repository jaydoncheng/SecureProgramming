.PHONY: all clean

CFLAGS=-g -Wall -Werror -UDEBUG -I$(INC_DIR)
LDLIBS=-lsqlite3 -lcrypto -lssl

OBJ_DIR=obj
SRC_DIR=src
INC_DIR=include

CLIENT_INC=api.h ui.h util.h
CLIENT_OBJS=client.o api.o util.o ui.o

SERVER_INC=util.h
SERVER_OBJS=server.o api.o util.o worker.o

all: client server

# compile any object matching .o with the relevant .c and .h files
# the -Iinclude flag in $(CFLAGS) makes gcc search include/ for the relevant .h files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c mkdir_obj
	gcc $(CFLAGS) -c $< -o $@ $(LDLIBS)

# client.o and server.o require extra headers (see the *_INC variables)
$(OBJ_DIR)/client.o: $(SRC_DIR)/client.c $(addprefix $(INC_DIR)/, $(CLIENT_INC))
$(OBJ_DIR)/server.o: $(SRC_DIR)/server.c $(addprefix $(INC_DIR)/, $(SERVER_INC))

client: $(addprefix $(OBJ_DIR)/, $(CLIENT_OBJS))
	gcc $^ -o client $(LDLIBS)

server: $(addprefix $(OBJ_DIR)/, $(SERVER_OBJS))
	gcc $^ -o server $(LDLIBS)

mkdir_obj:
	mkdir -p $(OBJ_DIR)

clean:
	rm -f server client $(OBJ_DIR)/*.o chat.db 