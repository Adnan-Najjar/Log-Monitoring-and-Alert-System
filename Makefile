CC = gcc
CFLAGS = -Ilib
SRC = src/logParser.c
EXEC = logParser

all: $(EXEC)

$(EXEC): $(SRC)
	$(CC) $(CFLAGS) -o bin/$@ $^

clean:
	rm -f $(EXEC)
