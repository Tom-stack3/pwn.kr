# Makefile for riddle.c

LEVEL = 1
CC = gcc
CFLAGS = -no-pie -O0 -m32 -g
TARGET = l$(LEVEL).out
SRC = l$(LEVEL).c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)