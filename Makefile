CC     = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -g
EXEC   = main
SRC    = main.c rsa_tools.c bezout.c phase1.c int2char.c other_base64.c
OBJ    = $(SRC:.c=.o)

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

mrproper: clean
	rm -f $(EXEC) keys_log logfp

.PHONY: all clean mrproper