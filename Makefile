CC      = gcc
CFLAGS  = -std=c99 -Wall -Wextra -pedantic -g

EXEC = test1 test2

COMMON_OBJ = rsa_tools.o bezout.o int2char.o other_base64.o
OBJ = test1.o test2.o phase1.o phase2.o $(COMMON_OBJ)

OUT_FILE = keys_log logfp image_decode.jpg image_base64.txt message_chiffrer message_dechiffre

all: $(EXEC)

test1: test1.o phase1.o $(COMMON_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ 

test2: test2.o phase2.o phase1.o $(COMMON_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ -lgmp

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

mrproper: clean
	rm -f $(EXEC) $(OUT_FILE)

.PHONY: all clean mrproper