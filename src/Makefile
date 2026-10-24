.PHONY: all clean

CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude
SOCKET_LIBS = -lws2_32 -lmswsock -ladvapi32
TARGET = main

all: main load

main:
	$(CC) $(CFLAGS) -o main load.c main.c $(SOCKET_LIBS)

load:
	$(CC) $(CFLAGS) -o load load.c load_main.c 

clean:
	del /q /f *.exe 2>nul || exit 0