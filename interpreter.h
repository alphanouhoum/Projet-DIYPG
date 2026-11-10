#ifndef INTERPRETER_H
#define INTERPRETER_H

#include "rsa_common_header.h"

#define MAX_KEYS 100
#define MAX_STR_LEN 64

// Structure pour stocker une paire de clefs et ses métadonnées
typedef struct {
    char id[MAX_STR_LEN];
    char type[MAX_STR_LEN]; // "crypt" ou "sign"
    keyPair_t keys;
} UserKey;

// L'annuaire complet
typedef struct {
    UserKey tab[MAX_KEYS];
    int count;
} KeyDirectory;

// Prototype principal
void start_interpreter();

#endif