#include "phase1.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* ============================================================
 * PHASE 1.0
 * ============================================================
 * */

void printKeyHex(const rsaKey_t *key)
{
    printf("E= 0x%llx, N=0x%llx\n", (unsigned long long)key->E, (unsigned long long)key->N);
}

void printKeyPairHex(const keyPair_t *kp)
{
    printf("Clé publique : ");
    printKeyHex(&kp->pubKey);

    printf("Clé prive : ");
    printKeyHex(&kp->privKey);
}

int saveKeys(const char *filename, const keyPair_t *kp)
{
    FILE *f = fopen(filename, "w");

    if (f == NULL)
    {
        return -1;
    }

    fprintf(f, "Clé publique : E= %llu  N= %llu\n", (unsigned long long)kp->pubKey.E, (unsigned long long)kp->pubKey.N);
    fprintf(f, "Clé privée   : E= %llu  N= %llu\n", (unsigned long long)kp->privKey.E, (unsigned long long)kp->privKey.N);
    fclose(f);

    return 0;
}

int loadKeys(const char *filename, keyPair_t *kp)
{
    FILE *f = fopen(filename, "r");

    if (f == NULL)
    {
        return -1;
    }

    // load de la cle publique

    if (fscanf(f, "Clé publique : E= %lu  N= %lu\n", &kp->pubKey.E, &kp->pubKey.N) != 2)
    {
        fclose(f);
        return -1;
    }

    // load de la cle prive
    if (fscanf(f, "Clé privée   : E= %lu  N= %lu\n", &kp->privKey.E, &kp->privKey.N) != 2)
    {
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

/* ============================================================
 * PHASE 1.1
 * ============================================================ */

uint8_t *chiffrer_tab_octet(const uint8_t *message, size_t taille, const rsaKey_t *pubKey)
{
    uint8_t *res = malloc(taille * NB_OCTETS_CHIFFRE);

    if (res == NULL)
        return NULL;

    for (size_t i = 0; i < taille; i++)
    {
        uint64_t caractere_chiffre = puissance_mod_n(message[i], pubKey->E, pubKey->N);
        
        // Stockage du résultat sur 8 octets 
        for (size_t j = 0; j < NB_OCTETS_CHIFFRE; j++)
        {
            res[i * NB_OCTETS_CHIFFRE + j] = (uint8_t)(caractere_chiffre >> (8 * j));
        }
    }

    return res;
}

uint8_t *dechiffrer_tab_octet(const uint8_t *message_chiffre, size_t taille, const rsaKey_t *privKey)
{
    size_t taille_message = taille / NB_OCTETS_CHIFFRE;
    uint8_t *res = malloc(taille_message+1);

    if (res == NULL)
        return NULL;

    for (size_t i = 0; i < taille_message; i++)
    {
        uint64_t chiffre = 0;

        // Reconstruction du nombre chiffré à partir des 8 octets
        for (size_t j = 0; j < NB_OCTETS_CHIFFRE; j++)
        {
                   //OU binaire 
            chiffre |= (uint64_t)message_chiffre[i * NB_OCTETS_CHIFFRE + j] << (8 * j);
        }

        uint64_t dechiffre = puissance_mod_n(chiffre, privKey->E, privKey->N);

        res[i] = (uint8_t)dechiffre;
    }

    res[taille_message] = '\0';

    
    return res;
}

/* ============================================================
 * PHASE 1.2
 * ============================================================ */

int chiffrer_fichier(const char *fichier_entree, const char *fichier_sortie, const rsaKey_t *pubKey)
{

    // ouverture du fichier entrer
    FILE *f_entree = fopen(fichier_entree, "rb");

    if (f_entree == NULL)
    {
        perror("Erreur d'ouverture du fichier d'entrer");
        return -1;
    }

    // Determination de la taille du fichier
    if (fseek(f_entree, 0, SEEK_END) != 0)
    {
        fclose(f_entree);
        return -1;
    }

    long taille_fichier = ftell(f_entree);

    
    rewind(f_entree);

    // Lecture du fichier
    size_t taille = (size_t)taille_fichier;
    uint8_t *message = malloc(taille);

    if (message == NULL)
    {
        fclose(f_entree);
        return -1;
    }

    if (fread(message, 1, taille, f_entree) != taille)
    {
        free(message);
        fclose(f_entree);
        perror("MESSAGE lu différent de Taille fichier\n");
        return -1;
    }

    fclose(f_entree);
    // chiffrement du message

    uint8_t *message_chiffrer = chiffrer_tab_octet(message, taille, pubKey);

    free(message);

    if (message_chiffrer == NULL)
    {
        fprintf(stderr,"Erreur de chiffrement\n");
        return -1;
    }

    // ouverture fichier sortie
    FILE *f_sortie = fopen(fichier_sortie, "wb");

    if (f_sortie == NULL)
    {
        free(message_chiffrer);
        return -1;
    }

    // Ecriture du message chiffre
    size_t taille_chiffree = taille * NB_OCTETS_CHIFFRE;

    fwrite(message_chiffrer, 1, taille_chiffree, f_sortie);
    free(message_chiffrer);
    fclose(f_sortie);

    return 0;
}

int dechiffrer_fichier(const char *fichier_entree, const char *fichier_sortie, const rsaKey_t *privKey)
{
    // ouverture du fichier entrer
    FILE *f_entree = fopen(fichier_entree, "rb");

    if (f_entree == NULL)
    {
        perror("Erreur d'ouverture du fichier d'entrer");
        return -1;
    }

    // Determination de la taille du fichier
    if (fseek(f_entree, 0, SEEK_END) != 0)
    {
        fclose(f_entree);
        return -1;
    }

    long taille_fichier = ftell(f_entree);

    rewind(f_entree);

    // Lecture du fichier
    size_t taille = (size_t)taille_fichier;
    uint8_t *message_chiffrer = malloc(taille);

    if (message_chiffrer == NULL)
    {
        fclose(f_entree);
        return -1;
    }

    if (fread(message_chiffrer, 1, taille, f_entree) != taille)
    {
        free(message_chiffrer);
        fclose(f_entree);
        perror("MESSAGE lu différent de Taille fichier\n");
        return -1;
    }

    fclose(f_entree);
    // dechiffrement du message

    uint8_t *message_dechiffrer = dechiffrer_tab_octet(message_chiffrer, taille, privKey);
    free(message_chiffrer);

    if (message_dechiffrer == NULL)
    {
        fprintf(stderr,"Erreur de déchiffrement\n");
        return -1;
    }

    FILE *f_sortie = fopen(fichier_sortie, "wb");

    if (f_sortie == NULL)
    {
        free(message_dechiffrer);
        return -1;
    }

    // Ecriture du message chiffre
    size_t taille_dechiffree = taille / NB_OCTETS_CHIFFRE;

    fwrite(message_dechiffrer, 1, taille_dechiffree, f_sortie);

    free(message_dechiffrer);
    fclose(f_sortie);

    return 0;
}

/* ============================================================
 * PHASE 1.3
 * ============================================================ */

char *uint8_to_base64(const uint8_t *message, size_t taille, size_t *taille_resultat)
{
    if (message == NULL && taille > 0)
        return NULL;

    if (taille_resultat == NULL)
        return NULL;

    char *resultat = base64_encode(
        message,
        taille,
        taille_resultat);

    if (resultat == NULL)
        return NULL;

    resultat[*taille_resultat] = '\0';

    return resultat;
}

uint8_t *base64_to_uint8(const char *message_base64, size_t taille, size_t *taille_resultat)
{
    if (message_base64 == NULL || taille_resultat == NULL)
        return NULL;

    unsigned char *resultat = base64_decode(
        message_base64,
        taille,
        taille_resultat);

    return resultat;
}

int fichier_binaire_vers_base64(const char *fichier_entree, const char *fichier_sortie)
{
    if (fichier_entree == NULL || fichier_sortie == NULL)
    {
        return -1;
    }

    FILE *fichier = fopen(fichier_entree, "rb");

    if (fichier == NULL)
    {
        perror("Erreur ouverture fichier binaire");
        return -1;
    }

    if (fseek(fichier, 0, SEEK_END) != 0)
    {
        perror("Erreur lecture taille fichier");
        fclose(fichier);
        return -1;
    }

    long taille_fichier = ftell(fichier);

    if (fseek(fichier, 0, SEEK_SET) != 0)
    {
        perror("Erreur retour debut fichier");
        fclose(fichier);
        return -1;
    }

    size_t taille = (size_t)taille_fichier;

    /* Lecture du fichier */
    uint8_t *message = malloc(taille);

    if (message == NULL)
    {
        fprintf(stderr, "Erreur allocation memoire.\n");
        fclose(fichier);
        return -1;
    }

    if (fread(message, 1, taille, fichier) != taille)
    {
        fprintf(stderr, "Erreur lecture fichier binaire.\n");
        free(message);
        fclose(fichier);
        return -1;
    }

    /* Encodage en Base64 */
    size_t taille_base64 = 0;

    char *resultat = uint8_to_base64(
        message,
        taille,
        &taille_base64);

    free(message);

    if (resultat == NULL)
    {
        fprintf(stderr, "Erreur encodage Base64.\n");
        return -1;
    }

    /* Ouverture du fichier de sortie */
    fichier = fopen(fichier_sortie, "wb");

    if (fichier == NULL)
    {
        perror("Erreur ouverture fichier Base64");
        free(resultat);
        return -1;
    }

    /* Écriture du résultat Base64 */
    if (fwrite(resultat, 1, taille_base64, fichier) != taille_base64)
    {
        perror("Erreur ecriture fichier Base64");
        free(resultat);
        fclose(fichier);
        return -1;
    }

    free(resultat);

    return 0;
}

int fichier_base64_vers_binaire(const char *fichier_entree, const char *fichier_sortie)
{
    if (fichier_entree == NULL || fichier_sortie == NULL)
        return -1;

    /* Ouverture du fichier Base64 en lecture */
    FILE *fichier = fopen(fichier_entree, "rb");

    if (fichier == NULL)
    {
        perror("Erreur ouverture fichier Base64");
        return -1;
    }

    /* Déterminer la taille du fichier */
    if (fseek(fichier, 0, SEEK_END) != 0)
    {
        perror("Erreur lecture taille fichier");
        fclose(fichier);
        return -1;
    }

    long taille_fichier = ftell(fichier);

    if (fseek(fichier, 0, SEEK_SET) != 0)
    {
        perror("Erreur retour debut fichier");
        fclose(fichier);
        return -1;
    }

    size_t taille = (size_t)taille_fichier;

    /* Lecture du fichier Base64 */
    char *message_base64 = malloc(taille);

    if (message_base64 == NULL)
    {
        fprintf(stderr, "Erreur allocation memoire.\n");
        fclose(fichier);
        return -1;
    }

    if (fread(message_base64, 1, taille, fichier) != taille)
    {
        fprintf(stderr, "Erreur lecture fichier Base64.\n");
        free(message_base64);
        fclose(fichier);
        return -1;
    }


    /* Décodage Base64 */
    size_t taille_binaire = 0;
    uint8_t *resultat;

    resultat = base64_to_uint8(
            message_base64,
            taille,
            &taille_binaire);
    

    free(message_base64);

    if (resultat == NULL)
    {
        fprintf(stderr, "Erreur decodage Base64.\n");
        return -1;
    }

    /* Création du fichier binaire de sortie */
    fichier = fopen(fichier_sortie, "wb");

    if (fichier == NULL)
    {
        perror("Erreur ouverture fichier binaire");
        free(resultat);
        return -1;
    }

    /* Écriture des octets décodés */
    if (fwrite(resultat, 1, taille_binaire, fichier) != taille_binaire)
    {
        perror("Erreur ecriture fichier binaire");
        free(resultat);
        fclose(fichier);
        return -1;
    }

    free(resultat);

    return 0;
}
