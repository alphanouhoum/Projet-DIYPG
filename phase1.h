#ifndef PHASE1_H
#define PHASE1_H

#include "rsa_common_header.h"


int64_t bezoutRSA(uint64_t a, uint64_t b, int64_t *u, int64_t *v);

/**
 * @return puissance modulaire, calcule a^e mod n
 */
uint64_t puissance_mod_n(uint64_t a, uint64_t e, uint64_t n);

/**
 * \brief test de primarité, crible d'Erathostène
 * @return 1 si le nombre est premier, 0 sinon
 **/ 
int premier(uint64_t n);

/**
 * \brief pgcd rapide de a et b
 * @param[in] a et b les deux entiers
 * @return pgcd(a,b)
 */
uint64_t pgcdFast(uint64_t a, uint64_t b);

/**
 * \brief génère une paire de "grandes" clefs, adaptées au cryptage RSA par bloc
 * @param[out] pubKey : clef publique
 * @param[out] privKey : clef privée
 */
void genKeysRabin(rsaKey_t *pubKey, rsaKey_t *privKey, uint64_t max_prime);

#endif