# Makefile for riddle.c

LEVEL = 4
CC = gcc
CFLAGS = -no-pie -O0 -m32 -g -fno-stack-protector
TARGET = l$(LEVEL).out
SRC = l$(LEVEL).c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)