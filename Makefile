CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -pthread -D_DEFAULT_SOURCE
LDFLAGS = -lsqlite3 -lssl -lcrypto -lconfig -lresolv

SRC = mail_server.c mail_db.c
OBJ = $(SRC:.c=.o)
TARGET = mail_server

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET) 

install:
	sudo apt-get install libssl-dev libsqlite3-dev libconfig-dev

.PHONY: all clean install
