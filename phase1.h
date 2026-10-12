#ifndef PHASE1_H
#define PHASE1_H

#include "rsa_common_header.h"

#define NB_OCTETS_CHIFFRE 4 
//chaque résultat chiffré est stocké sur 4 octets.


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


/** affiche une clef au format hexadécimal : "(E=0x..., N=0x...)" */
void printKeyHex(const rsaKey_t *key);

/** affiche une paire de clefs (publique puis privée) en hexadécimal */
void printKeyPairHex(const keyPair_t *kp);

/** sauve une paire de clefs dans un fichier texte (hexa). 
 * @return 0 si OK, -1 sinon 
 * */
int saveKeys(const char *filename, const keyPair_t *kp);

/** charge une paire de clefs depuis un fichier. 
 * @return 0 si OK, -1 sinon
 * */
int loadKeys(const char *filename, keyPair_t *kp);

// conversion 4 octets en un int
uint32_t convert_4byte2int(uint8_t *b);

// conversion 1 int en 4 octets
void convertInt2uchar(uint32_t nb,uint8_t *tab4bytes);

/** 
 * @brief chiffrer un tableau d'octet. 
 * @param[in] message le tableau d'octet a chiffrer
 * @param[in] taille : taille du tableau
 * @param[in] pubKey : la clé publique utilisée pour le chiffrement
 * @return un tableau d'octet chiffrer, ou NULL en cas d'erreur
 * */
uint8_t *chiffrer_tab_octet (const uint8_t *message, size_t taille, const rsaKey_t *pubKey);

/** 
 * @brief dechiffrer un tableau d'octet. 
 * @param[in] message Message à déchiffrer
 * @param[in] taille : taille Taille du message en octets.
 * @param[in] privKey : la clé prive utilisée pour le dechiffrement
 * @return le message dechiffrer, ou NULL en cas d'erreur
 * */
uint8_t *dechiffrer_tab_octet(const uint8_t *message_chiffre, size_t taille, const rsaKey_t *privKey);

/** 
 * @brief Chiffre le contenu d'un fichier et écrit le résultat dans un autre fichier.
 * @param[in] fichier_entree Chemin du fichier contenant le message original.
 * @param[in] fichier_sortie Chemin du fichier qui recevra le message chiffré.
 * @param[in] pubKey Clé publique utilisée pour le chiffrement.
 *
 * @return 0 si le chiffrement réussit, -1 en cas d'erreur.
 */
int chiffrer_fichier(const char *fichier_entree, const char *fichier_sortie, const rsaKey_t *pubKey);

/** 
 * @brief dechiffre le contenu d'un fichier et écrit le résultat dans un autre fichier.
 * @param[in] fichier_entree Chemin du fichier contenant le message chiffrer.
 * @param[in] fichier_sortie Chemin du fichier qui recevra le message déchiffré.
 * @param[in] privKey Clé publique utilisée pour le déchiffrement.
 *
 * @return 0 si le déchiffrement réussit, -1 en cas d'erreur.
 */
int dechiffrer_fichier(const char *fichier_entree, const char *fichier_sortie, const rsaKey_t *privKey);


#endif