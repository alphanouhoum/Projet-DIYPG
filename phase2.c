#include <stdio.h>
#include <stdint.h>
#include <gmp.h>
#include <string.h>
#include "rsa_common_header.h"
#include "phase2.h"


void puissance_mod_n_gmp(mpz_t res, uint64_t a, uint64_t e, uint64_t n)
{
    mpz_t base, exposant, modulo;

    //initialise une variable GMP
    mpz_init(base);
    mpz_init(exposant);
    mpz_init(modulo);

    //copie un entier dans une variable GMP.
    mpz_set_ui(base, a);
    mpz_set_ui(exposant, e);
    mpz_set_ui(modulo, n);

    //calcul de puissance 
    mpz_powm(res, base, exposant, modulo);

    //libere la memoir
    mpz_clear(base);
    mpz_clear(exposant);
    mpz_clear(modulo);
}


int chiffrer_tab_octetV2(const uint8_t *message, size_t taille, const rsaKey_t *pubKey, tab_bloc_t *info_chiffrer)
{
    info_chiffrer->taille_msg = taille;

    info_chiffrer->nb_blocs = (info_chiffrer->taille_msg + NB_OCTETS_BLOC-1)/NB_OCTETS_BLOC;

    info_chiffrer->res_blocs = malloc(info_chiffrer->nb_blocs * sizeof(uint64_t));

    if (info_chiffrer->res_blocs == NULL)
    {
        return -1;
    }
    
    mpz_t resultat;
    mpz_init(resultat);
    for (size_t i = 0; i < info_chiffrer->nb_blocs; i++)
    {
        uint8_t bloc[NB_OCTETS_BLOC] = {0}; //tableau initialiser de 0 

        size_t debut_bloc = i * NB_OCTETS_BLOC;
        size_t octets_restants = info_chiffrer->taille_msg - debut_bloc; // 4 ou moin pour le dernier bloc
        size_t octets_a_copier;

        if (octets_restants < NB_OCTETS_BLOC) 
        {
            octets_a_copier = octets_restants;
        }else{
            octets_a_copier = NB_OCTETS_BLOC;
        }

        //copi des octets a copie dans bloc  
        memcpy(bloc, message + debut_bloc, octets_a_copier);
        //printf("Bloc %ld : %s\n", i, bloc);
        uint32_t nombre = convert_4byte2int(bloc); //nombre obetenu par la conversion du bloc
       
        puissance_mod_n_gmp(resultat, nombre, pubKey->E, pubKey->N);
    
        info_chiffrer->res_blocs[i] = mpz_get_ui(resultat); //ne recuperer que les nombre sur 64 bits
    }
    mpz_clear(resultat);
    return 0;
}

uint8_t *dechiffrer_tab_octetV2(tab_bloc_t *info_chiffrer,const rsaKey_t *privKey){
    uint8_t *res = malloc(info_chiffrer->taille_msg+1 );
    
    if(res == NULL){
        return NULL;
    }

    mpz_t resultat;
    mpz_init(resultat);

    for (size_t i = 0; i < info_chiffrer->nb_blocs; i++)
    {
        puissance_mod_n_gmp(resultat, info_chiffrer->res_blocs[i], privKey->E, privKey->N);

        uint32_t nombre = mpz_get_ui(resultat);
        printf("bloc %ld -> Nombre dechiffrer : %u\n", i,  nombre);

        uint8_t bloc[NB_OCTETS_BLOC];

        convertInt2uchar(nombre, bloc);

        // on ne copie que les octets utiles
        size_t debut_bloc = i * NB_OCTETS_BLOC;
        size_t restants = info_chiffrer->taille_msg - debut_bloc;
        size_t octets_a_copier;
        if (restants < NB_OCTETS_BLOC)
        {
            octets_a_copier = restants;
        }else{
            octets_a_copier = NB_OCTETS_BLOC;
        }
        
        memcpy(res + debut_bloc, bloc, octets_a_copier);
        
    }

    mpz_clear(resultat);

    res[info_chiffrer->taille_msg] = '\0';
    return res;
    

}

int chiffrer_fichierV2(const char *fichier_entree, const char *fichier_sortie, const rsaKey_t *pubKey, tab_bloc_t *info_chiffrer)
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

    int res_chiffrage = chiffrer_tab_octetV2(message, taille, pubKey, info_chiffrer);

    free(message);

    if (res_chiffrage != 0)
    {
        fprintf(stderr,"Erreur de chiffrement\n");
        return -1;
    }

    // ouverture fichier sortie
    FILE *f_sortie = fopen(fichier_sortie, "wb");

    if (f_sortie == NULL)
    {
        free(info_chiffrer->res_blocs);
        return -1;
    }

    // Ecriture du message chiffre
    size_t taille_chiffree = taille * NB_OCTETS_CHIFFRE;

    fwrite(info_chiffrer->res_blocs, 1, taille_chiffree, f_sortie);
    fclose(f_sortie);

    return 0;
}


int dechiffrer_fichierV2(const char *fichier_entree, const char *fichier_sortie, const rsaKey_t *privKey, tab_bloc_t *info_chiffrer)
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

    uint8_t *message_dechiffrer = dechiffrer_tab_octetV2(info_chiffrer, privKey);
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
