CC      = gcc
CFLAGS  = -std=c99 -Wall -Wextra -pedantic -g

EXEC = main

COMMON_OBJ = rsa_tools.o bezout.o int2char.o other_base64.o
OBJ = test1.o test2.o phase1.o phase2.o interpreter.o main.o $(COMMON_OBJ)

IMG = image_chiffree image_dechiffree.jpg
MESSAGE = message_chiffrer message_dechiffre
BASE64 = image_decode.jpg image_base64.txt
OUT_FILE = keys_log logfp $(BASE64) $(MESSAGE) $(IMG)

all: $(EXEC)

main: main.o phase1.o phase2.o interpreter.o $(COMMON_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ -lgmp

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