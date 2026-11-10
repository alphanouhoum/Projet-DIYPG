#include <stdio.h>
#include <stdint.h>
#include <gmp.h>
#include <string.h>
#include "rsa_common_header.h"
#include "phase2.h"


static void init_tab_bloc(tab_bloc_t *info)
{
    info->res_blocs = NULL;
    info->nb_blocs = 0;
    info->taille_msg = 0;
}


static uint8_t *lire_fichier(const char *nom, size_t *taille)
{
    FILE *f = fopen(nom, "rb");
    if (f == NULL) { 
        perror("Ouverture fichier"); 
        return NULL; 
    }
 
    if (fseek(f, 0, SEEK_END) != 0) { 
        fclose(f); return NULL; 
    }

    long t = ftell(f);
    if (t < 0) {
        fclose(f); return NULL; 
    }
    rewind(f);
 
    uint8_t *buf = malloc(t > 0 ? (size_t)t : 1);   /* evite malloc(0) */
    if (!buf) { 
        fclose(f); 
        return NULL; 
    }
 
    if (fread(buf, 1, (size_t)t, f) != (size_t)t) {
        fprintf(stderr, "Lecture incomplete de %s\n", nom);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *taille = (size_t)t;
    return buf;
}

static int ecrire_fichier(const char *nom, const uint8_t *data, size_t taille)
{
    FILE *f = fopen(nom, "wb");
    if (f == NULL) { 
        perror("Ouverture fichier de sortie"); 
        return -1; 
    }
 
    size_t ecrit = fwrite(data, 1, taille, f);
    
    if (ecrit != taille) {
        perror("Erreur fwrite");
        fprintf(stderr, "Octets ecrits : %zu / %zu\n", ecrit, taille);
        fclose(f);
        return -1;
    }

    fclose(f);

    return 0;
}

static void ecrire_header(uint8_t *out, uint64_t v)
{
    for (int j = 0; j < 8; j++)
        out[j] = (uint8_t)(v >> (8 * j));
}
 
static uint64_t lire_header(const uint8_t *in)
{
    uint64_t v = 0;
    for (int j = 0; j < 8; j++)
        v |= (uint64_t)in[j] << (8 * j);
    return v;
}


void liberer_tab_bloc(tab_bloc_t *info)
{
    free(info->res_blocs);   
    init_tab_bloc(info);     
}


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
    if (taille < 1)
    {
        fprintf(stderr, "Message Vide\n");
        return -1;
    }
    
    init_tab_bloc(info_chiffrer);

    
    if (pubKey->N <= UINT32_MAX) {
        fprintf(stderr, "N doit etre > 2^32 pour des blocs de 4 octets\n");
        printf("N = %lu\n", pubKey->N);
        return -1;
    }
    


    info_chiffrer->taille_msg = taille;
    info_chiffrer->nb_blocs = (info_chiffrer->taille_msg + NB_OCTETS_BLOC-1) / NB_OCTETS_BLOC;
    info_chiffrer->res_blocs = malloc(info_chiffrer->nb_blocs * sizeof(uint64_t));


    if (info_chiffrer->res_blocs == NULL)
    {
        init_tab_bloc(info_chiffrer);
        return -1;
    }
    
    mpz_t resultat;
    mpz_init(resultat);
    for (size_t i = 0; i < info_chiffrer->nb_blocs; i++)
    {
        uint8_t bloc[NB_OCTETS_BLOC] = {0}; //tableau initialiser de 0 

        size_t debut_bloc = i * NB_OCTETS_BLOC;
        size_t octets_restants = taille - debut_bloc; // 4 ou moin pour le dernier bloc
        size_t octets_a_copier;

        if (octets_restants < NB_OCTETS_BLOC) 
        {
            octets_a_copier = octets_restants;
        }else{
            octets_a_copier = NB_OCTETS_BLOC;
        }

        //copi des octets a copie dans bloc  
        memcpy(bloc, message + debut_bloc, octets_a_copier);
        
        uint32_t nombre = convert_4byte2int(bloc); //nombre obetenu par la conversion du bloc
       
        puissance_mod_n_gmp(resultat, nombre, pubKey->E, pubKey->N);
    
        info_chiffrer->res_blocs[i] = mpz_get_ui(resultat); //ne recuperer que les nombre sur 64 bits
    }
    mpz_clear(resultat);
    return 0;
}

uint8_t *dechiffrer_tab_octetV2(tab_bloc_t *info_chiffrer,const rsaKey_t *privKey){
    
    uint8_t *res = malloc(info_chiffrer->taille_msg+1 );
    if(res == NULL)
        return NULL;
    

    mpz_t resultat;
    mpz_init(resultat);

    for (size_t i = 0; i < info_chiffrer->nb_blocs; i++)
    {
        puissance_mod_n_gmp(resultat, info_chiffrer->res_blocs[i], privKey->E, privKey->N);

        uint32_t nombre = mpz_get_ui(resultat);

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

int chiffrer_fichierV2(const char *fichier_entree, const char *fichier_sortie, const rsaKey_t *pubKey)
{
    tab_bloc_t info;
    init_tab_bloc(&info);

    //Lecture du fichier 
    size_t taille;
    uint8_t *message = lire_fichier(fichier_entree, &taille);
    if (!message){
        return -1;
    }   

    int res_chiffrage = chiffrer_tab_octetV2(message, taille, pubKey, &info);
    free(message);  //info.res contient la data chiffre
    if (res_chiffrage != 0)
    {
        fprintf(stderr, "Erreur de chiffrement\n");
        return -1;

    }

    /* Construction du buffer de sortie = en-tete (taille_msg) + blocs chiffres */
    size_t taille_out = 8 + info.nb_blocs * NB_OCTETS_CHIFFRE;
    uint8_t *out = malloc(taille_out);
    if (!out) {
        liberer_tab_bloc(&info);
        return -1;
    }

    ecrire_header(out, (uint64_t)info.taille_msg);
    for (size_t i = 0; i < info.nb_blocs; i++)
        ecrire_header(out + 8 + i * NB_OCTETS_CHIFFRE, info.res_blocs[i]);
 
    
    res_chiffrage = ecrire_fichier(fichier_sortie, out, taille_out);
 
    free(out);
    liberer_tab_bloc(&info);
    return res_chiffrage;
}


int dechiffrer_fichierV2(const char *fichier_entree, const char *fichier_sortie, const rsaKey_t *privKey) {

    tab_bloc_t info;
    init_tab_bloc(&info);
 
    size_t taille;
    uint8_t *buf = lire_fichier(fichier_entree, &taille);
    if (!buf)
        return -1;
 
    if (taille < 8 || (taille - 8) % NB_OCTETS_CHIFFRE != 0) {
        fprintf(stderr, "Fichier chiffre invalide\n");
        free(buf);
        return -1;
    }
 
    // Récupérer la taille originale
    uint64_t taille_msg = lire_header(buf);
    size_t nb_blocs = (taille - 8) / NB_OCTETS_CHIFFRE;
 
   
    if (taille_msg / NB_OCTETS_BLOC + (taille_msg % NB_OCTETS_BLOC != 0) != nb_blocs) {
        fprintf(stderr, "En-tete incoherent\n");
        free(buf);
        return -1;
    }

    // Reconstruire le tableau des blocs chiffrés

    info.taille_msg = (size_t)taille_msg;
    info.nb_blocs = nb_blocs;
    info.res_blocs = malloc((nb_blocs ? nb_blocs : 1) * sizeof(uint64_t));
    if (info.res_blocs == NULL) {
        free(buf);
        init_tab_bloc(&info);
        return -1;
    }

    for (size_t i = 0; i < nb_blocs; i++)
        info.res_blocs[i] = lire_header(buf + 8 + i * NB_OCTETS_CHIFFRE);
    free(buf);


    // Déchiffrement des blocs
    uint8_t *clair = dechiffrer_tab_octetV2(&info, privKey);
    size_t taille_clair = info.taille_msg;
    liberer_tab_bloc(&info);
    if (!clair) {
        fprintf(stderr, "Erreur de dechiffrement\n");
        return -1;
    }
 
    int r = ecrire_fichier(fichier_sortie, clair, taille_clair);
    free(clair);
    return r;

}


