.PHONY: all clean

CC = gcc
CFLAGS = -Wall -Wextra -O2
SOCKET_LIBS = -lws2_32 -lmswsock -ladvapi32
TARGET = main

all: $(TARGET)

main:
	$(CC) $(CFLAGS) -o $(TARGET) main.c $(SOCKET_LIBS)

clean:
	del /q /f *.exe 2>nul || exit 0