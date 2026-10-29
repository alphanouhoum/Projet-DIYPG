CC     = gcc
CFLAGS = -std=c99 -Wall -Wextra -pedantic -g -lgmp
EXEC   = test1
SRC    = test1.c rsa_tools.c bezout.c phase1.c int2char.c other_base64.c
OBJ    = $(SRC:.c=.o)
OUT_FILE   =  keys_log logfp image_decode.jpg image_base64.txt message_chiffrer message_dechiffre

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

mrproper: clean
	rm -f $(EXEC) $(OUT_FILE)

.PHONY: all clean mrproper