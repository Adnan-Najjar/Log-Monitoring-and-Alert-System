CC = gcc
SRC = src/logParser.c
EXEC = logParser

all: $(EXEC)

$(EXEC): $(SRC)
	$(CC) -o bin/$@ $^

clean:
	rm -f $(EXEC)
