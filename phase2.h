#ifndef PHASE2_H
#define PHASE2_H

#include <gmp.h>
#include "rsa_common_header.h"

#define NB_OCTETS_BLOC 4
#define NB_OCTETS_CHIFFRE 8

typedef struct tab_bloc_s{
    uint64_t *res_blocs;
    size_t nb_blocs;
    size_t taille_msg;

} tab_bloc_t;


// conversion de 4 octets en un int
uint32_t convert_4byte2int(uint8_t *b);

// conversion d'un int en 4 octets
void convertInt2uchar(uint32_t nb,uint8_t *tab4bytes);



void puissance_mod_n_gmp(mpz_t res, uint64_t a, uint64_t e, uint64_t n);

int chiffrer_tab_octetV2(const uint8_t *message, size_t taille, const rsaKey_t *pubKey, tab_bloc_t *info_chiffrer);

uint8_t *dechiffrer_tab_octetV2(tab_bloc_t *info_chiffrer, const rsaKey_t *privKey);

int chiffrer_fichierV2(const char *fichier_entree, const char *fichier_sortie, const rsaKey_t *pubKey, tab_bloc_t *info_chiffrer);

int dechiffrer_fichierV2(const char *fichier_entree, const char *fichier_sortie, const rsaKey_t *privKey, tab_bloc_t *info_chiffrer);


#endif