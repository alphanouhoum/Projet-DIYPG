CC     = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -g
EXEC   = rsa
SRC    = main.c rsa_tools.c bezout.c
OBJ    = $(SRC:.c=.o)

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

mrproper: clean
	rm -f $(EXEC)

.PHONY: all clean mrproper