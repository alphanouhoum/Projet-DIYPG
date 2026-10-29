#ifndef PHASE1_H
#define PHASE1_H

#include "rsa_common_header.h"

#define NB_OCTETS_CHIFFRE 8 //chaque résultat chiffré est stocké sur 8 octets.


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

/** sauve une paire de clefs dans un fichier texte. 
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


/**
 * @brief Encode un tableau d'octets en Base64.
 *
 * @param data Tableau d'octets à encoder.
 * @param input_length Taille du tableau d'octets à encoder.
 * @param output_length Pointeur vers une variable qui recevra la taille du résultat encodé.
 *                     
 * @return Un pointeur vers la chaîne Base64 allouée dynamiquement,
 *         ou NULL en cas d'erreur.
 */
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);

/**
 * @brief Décode une chaîne Base64 en tableau d'octets.
 *
 * @param[in] data Chaîne contenant les données encodées en Base64.
 * @param[in] input_length Taille de la chaîne Base64 à décoder.
 * @param[out] output_length Adresse où sera enregistrée la taille du résultat.
 *
 * @return Un pointeur vers le tableau d'octets décodé, NULL en cas d'erreur.
 */
unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length);

/**
 * @brief Convertit un tableau d'octets en chaîne de caractères Base64.
 *
 * @param[in] message Tableau d'octets à encoder.
 * @param[in] taille Nombre d'octets du message.
 * @param[out] taille_resultat Adresse où sera enregistrée la taille du résultat.
 *
 * @return Un pointeur vers la chaîne Base64 obtenue, NULL en cas d'erreur.
 */
char *uint8_to_base64(const uint8_t *message, size_t taille, size_t *taille_resultat);

/**
 * @brief Convertit une chaîne Base64 en tableau d'octets.
 *
 * @param[in] message_base64 Chaîne contenant les données encodées en Base64.
 * @param[in] taille Taille de la chaîne Base64 à décoder.
 * @param[out] taille_resultat Adresse où sera enregistrée la taille du tableau obtenu.
 *
 * @return Un pointeur vers le tableau d'octets décodé, NULL en cas d'erreur.
 *
 */
uint8_t *base64_to_uint8(const char *message_base64, size_t taille, size_t *taille_resultat);

/**
 * @brief Convertit un fichier binaire en fichier encodé en Base64.
 *
 * @param[in] fichier_entree Chemin du fichier binaire à encoder.
 * @param[in] fichier_sortie Chemin du fichier qui recevra le contenu encodé en Base64.
 *
 * @return 0 si la conversion réussit, -1 en cas d'erreur.
 */
int fichier_binaire_vers_base64(const char *fichier_entree, const char *fichier_sortie);

/**
 * @brief Convertit un fichier Base64 en fichier binaire.
 *
 * @param[in] fichier_entree Chemin du fichier contenant les données encodées en Base64.
 * @param[in] fichier_sortie Chemin du fichier qui recevra les données binaires décodées.
 *
 * @return 0 si la conversion réussit, -1 en cas d'erreur.
 */
int fichier_base64_vers_binaire(const char *fichier_entree, const char *fichier_sortie);



#endif