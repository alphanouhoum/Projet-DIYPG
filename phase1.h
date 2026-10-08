#ifndef PHASE1_H
#define PHASE1_H

#include "rsa_common_header.h"

int64_t bezoutRSA(uint64_t a, uint64_t b, int64_t *u, int64_t *v);
uint64_t puissance_mod_n(uint64_t a, uint64_t e, uint64_t n);
int premier(uint64_t n);
uint64_t pgcdFast(uint64_t a, uint64_t b);
void genKeysRabin(rsaKey_t *pubKey, rsaKey_t *privKey, uint64_t max_prime);

#endif
