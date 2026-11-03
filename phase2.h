#ifndef PHASE2_H
#define PHASE2_H

#include <gmp.h>
#include "rsa_common_header.h"

#define NB_OCTETS_BLOC 4
#define NB_OCTETS_CHIFFRE 8


/**
 * @brief Structure contenant les informations relatives à un message chiffré sous forme de blocs.
 *
 * @param res_blocs Tableau contenant les blocs du message chiffré.
 * @param nb_blocs Nombre de blocs composant le message chiffré.
 * @param taille_msg Taille initiale du message.
 */
typedef struct tab_bloc_s{
    uint64_t *res_blocs;
    size_t nb_blocs;
    size_t taille_msg;

} tab_bloc_t;


/**
 * @brief Convertit 4 octets en un entier non signé de 32 bits.
 *
 * @param[in] b Tableau contenant les 4 octets à convertir.
 *
 * @return Entier de 32 bits correspondant aux 4 octets.
 */
uint32_t convert_4byte2int(uint8_t *b);


/**
 * @brief Convertit un entier non signé de 32 bits en 4 octets.
 *
 * @param[in] nb Entier à convertir.
 * @param[out] tab4bytes Tableau de 4 octets qui recevra le résultat de la conversion.
 */
void convertInt2uchar(uint32_t nb,uint8_t *tab4bytes);


/**
 * @brief Calcule la puissance modulaire d'un entier à l'aide de la bibliothèque GMP.
 *
 * @param[out] res Variable GMP qui recevra le résultat du calcul.
 * @param[in] a Base de l'exponentiation.
 * @param[in] e Exposant.
 * @param[in] n Modulo utilisé pour le calcul.
 */
void puissance_mod_n_gmp(mpz_t res, uint64_t a, uint64_t e, uint64_t n);


/**
 * @brief Chiffre un tableau d'octets à l'aide d'une clé publique RSA.
 *
 * @param[in] message Tableau d'octets contenant le message à chiffrer.
 * @param[in] taille Taille du message en octets.
 * @param[in] pubKey Clé publique RSA utilisée pour le chiffrement.
 * @param[out] info_chiffrer Structure qui recevra les blocs chiffrés ainsi que les informations sur le message initial.
 *
 * @return 0 si le chiffrement réussit, -1 en cas d'erreur.
 */
int chiffrer_tab_octetV2(const uint8_t *message, size_t taille, const rsaKey_t *pubKey, tab_bloc_t *info_chiffrer);

/**
 * @brief Déchiffre un tableau de blocs à l'aide d'une clé privée RSA.
 *
 * @param[in] info_chiffrer Structure contenant les blocs chiffrés et les informations sur le message initial.
 * @param[in] privKey Clé privée RSA utilisée pour le déchiffrement.
 *
 * @return Pointeur vers le tableau d'octets contenant le message déchiffré, ou NULL en cas d'erreur.
 */
uint8_t *dechiffrer_tab_octetV2(tab_bloc_t *info_chiffrer, const rsaKey_t *privKey);


/**
 * @brief Chiffre le contenu d'un fichier à l'aide d'une clé publique RSA.
 *
 * @param[in] fichier_entree Chemin du fichier contenant les données à chiffrer.
 * @param[in] fichier_sortie nom du fichier qui recevra les données chiffrées.
 * @param[in] pubKey Clé publique RSA utilisée pour le chiffrement.
 * @param[out] info_chiffrer Structure qui recevra les informations relatives aux blocs chiffrés.
 *
 * @return 0 si le chiffrement réussit, -1 en cas d'erreur.
 */
int chiffrer_fichierV2(const char *fichier_entree, const char *fichier_sortie, const rsaKey_t *pubKey, tab_bloc_t *info_chiffrer);

/**
 * @brief Déchiffre le contenu d'un fichier à l'aide d'une clé privé RSA.
 *
 * @param[in] fichier_entree Chemin du fichier contenant les données à chiffrer.
 * @param[in] fichier_sortie nom du fichier qui recevra les données chiffrées.
 * @param[in] pubKey Clé privé RSA utilisée pour le déchiffrement.
 * @param[out] info_chiffrer Structure contenant les informations relatives aux blocs chiffrés.
 *
 * @return 0 si le chiffrement réussit, -1 en cas d'erreur.
 */
int dechiffrer_fichierV2(const char *fichier_entree, const char *fichier_sortie, const rsaKey_t *privKey, tab_bloc_t *info_chiffrer);

/**
 * @brief Encode un tableau d'octets en Base64.
 *
 * @param[in] data Tableau d'octets contenant les données à encoder.
 * @param[in] input_length Taille des données d'entrée en octets.
 * @param[out] output_length Pointeur vers une variable qui recevra la taille du résultat encodé.
 *
 * @return Pointeur vers la chaîne de caractères contenant les données encodées en Base64, ou NULL en cas d'erreur.
 */
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);



/**
 * @brief Décode une chaîne Base64 en un tableau d'octets.
 *
 * @param[in] data Chaîne contenant les données encodées en Base64.
 * @param[in] input_length Taille de la chaîne Base64 en octets.
 * @param[out] output_length Pointeur vers une variable qui recevra la taille des données décodées.
 *
 * @return Pointeur vers le tableau d'octets contenant les données décodées, ou NULL en cas d'erreur.
 */
unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length);


#endif