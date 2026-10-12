#include "phase1.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* ============================================================
 * PHASE 1.0 
 * ============================================================ 
 * */

void printKeyHex(const rsaKey_t *key){
    printf("E= 0x%llx, N=0x%llx\n", (unsigned long long)key->E, (unsigned long long)key->N);
}


void printKeyPairHex(const keyPair_t *kp){
    printf("Clé publique : ");
    printKeyHex(&kp->pubKey);

    printf("Clé prive : ");
    printKeyHex(&kp->privKey);
}

int saveKeys(const char *filename, const keyPair_t *kp){
    FILE *f = fopen(filename, "w");

    if (f == NULL)
    {
        return -1;
    }

    fprintf(f, "%llu  %llu\n", (unsigned long long)kp->pubKey.E, (unsigned long long)kp->pubKey.N);
    fprintf(f, "%llu  %llu\n", (unsigned long long)kp->privKey.E, (unsigned long long)kp->privKey.N);
    fclose(f);

    return 0;
    
}

int loadKeys(const char *filename, keyPair_t *kp){
    FILE *f = fopen(filename, "r");

    if (f == NULL)
    {
        return -1;
    }


    //load de la cle publique

    if(fscanf(f, "%llu  %llu", (unsigned long long)&kp->pubKey.E, (unsigned long long)&kp->pubKey.N ) != 2){
        fclose(f);
        return -1;
    }

    //load de la cle prive 
    if(fscanf(f, "%llu  %llu", (unsigned long long)&kp->privKey.E, (unsigned long long)&kp->privKey.N) != 2){
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

/* ============================================================
 * PHASE 1.1 
 * ============================================================ */

uint8_t * chiffrer_tab_octet (const uint8_t *message, size_t taille, const rsaKey_t *pubKey){

    uint8_t *res = malloc(taille * NB_OCTETS_CHIFFRE); 
    if (res == NULL) return NULL;   

    for (size_t i = 0; i < taille; i++)
    {
        uint64_t caractere_chiffre = puissance_mod_n(message[i], pubKey->E, pubKey->N);
        convertInt2uchar((uint32_t)caractere_chiffre, &res[i * NB_OCTETS_CHIFFRE]);
    }

    return res;
    
}

uint8_t *dechiffrer_tab_octet(const uint8_t *message_chiffre, size_t taille, const rsaKey_t *privKey){
    size_t taille_message = taille / NB_OCTETS_CHIFFRE;
    uint8_t *res = malloc(taille_message);
    if (res == NULL) return NULL;

    for ( size_t i = 0; i < taille_message; i++)
    {
        uint32_t caractere_chiffre = convert_4byte2int((uint8_t *)&message_chiffre[i * NB_OCTETS_CHIFFRE]);
        
        res[i] = (uint8_t)puissance_mod_n(caractere_chiffre, privKey->E, privKey->N);
    }

    res[taille_message] = '\0';
    return res;
    
}

/* ============================================================
 * PHASE 1.2
 * ============================================================ */


int chiffrer_fichier(const char *fichier_entree, const char *fichier_sortie, const rsaKey_t *pubKey){
    
    //ouverture du fichier entrer
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

    //fichier vide 
    if (taille_fichier < 0)
    {
        fclose(f_entree);
        return -1;
    }
    rewind(f_entree);

    //Lecture du fichier
    size_t taille = (size_t)taille_fichier;
    uint8_t *message = malloc(taille);
    
    if (message == NULL)
    {
        fclose(f_entree);
        return -1;
    }

    if(fread(message, 1, taille, f_entree) != taille){
        free(message);
        fclose(f_entree);
        printf("MESSAGE lu différent de Taille fichier\n");
        return -1;
    }

    fclose(f_entree);
    //chiffrement du message 

    uint8_t *message_chiffrer = chiffrer_tab_octet(message, taille, pubKey);

    free(message);

    if (message_chiffrer == NULL)
    {
        return -1;
    }

    //ouverture fichier sortie
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

int dechiffrer_fichier(const char *fichier_entree, const char *fichier_sortie, const rsaKey_t *privKey){
    //ouverture du fichier entrer
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

    //fichier vide 
    if (taille_fichier < 0)
    {
        fclose(f_entree);
        return -1;
    }
    rewind(f_entree);

    //Lecture du fichier
    size_t taille = (size_t)taille_fichier;
    uint8_t *message_chiffrer = malloc(taille);
    
    if (message_chiffrer == NULL)
    {
        fclose(f_entree);
        return -1;
    }

    if(fread(message_chiffrer, 1, taille, f_entree) != taille){
        free(message_chiffrer);
        fclose(f_entree);
        printf("MESSAGE lu différent de Taille fichier\n");
        return -1;
    }

    fclose(f_entree);
    //dechiffrement du message
    
    uint8_t *message_dechiffrer = dechiffrer_tab_octet(message_chiffrer, taille, privKey);
    free(message_chiffrer);

    if (message_dechiffrer == NULL)
    {
        perror("Erreur de dechiffrement");
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