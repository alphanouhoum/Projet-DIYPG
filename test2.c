#include <stdio.h>
#include <stdint.h>

#include "phase1.h"
#include "phase2.h"
#include "rsa_common_header.h"

FILE *logfp;

void test_chiffrement_bloc(){

    printf("========== Test Chiffrage par boc ==========\n");
    uint8_t msg[] = "Aujourd'hui est un beau jour pour teste une fonction de chiffrement RSA !";
    
    keyPair_t rsa_key;
    genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);

    printKeyPairHex(&rsa_key);

    size_t taille_msg =  sizeof(msg)-1;

    tab_bloc_t info_blocs;

    chiffrer_tab_octetV2(msg, taille_msg, &rsa_key.pubKey, &info_blocs);

    //Dechiffrement par bloc
    uint8_t *res_dechiffrer = dechiffrer_tab_octetV2(&info_blocs, &rsa_key.privKey); 

    printf("Message de original  : %s\n", msg);
    //printf("Message chiffrer     : %ln\n", info_blocs.res_blocs);
    printf("Message dechiffrer   : %s\n", (char *) res_dechiffrer);

    free(info_blocs.res_blocs);
}

void test_chiffrement_dechiffrement_fichier(){
  printf("\n========== TEST chiffrement et déchiffrement fichier ==========\n");

  keyPair_t rsa_key;
  genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);

  char *fichier_entrer = "./message";
  char *fichier_sortie = "message_chiffrer";
  char *fichier_dechiffre = "message_dechiffre";

  tab_bloc_t info_chiffrer;
  int res = chiffrer_fichierV2(fichier_entrer, fichier_sortie, &rsa_key.pubKey, &info_chiffrer);

  printf(res == 0 ? "TEST OK Chiffrement\n" : "TEST Echec Chiffrement\n");
  printf("Fichier chiffrer : %s -> %s\n", fichier_entrer, fichier_sortie);

  // dechiffrement du fichier
  res = dechiffrer_fichierV2(fichier_sortie, fichier_dechiffre, &rsa_key.privKey, &info_chiffrer);

  printf(res == 0 ? "TEST OK Dechiffrement\n" : "TEST Echec Dechiffrement\n");
  printf("Fichier dechiffrer : %s -> %s\n", fichier_sortie, fichier_dechiffre);

}

void test_base64(){
    printf("\n========== Test conversion cé bas64 ==========\n");

    keyPair_t rsa_key;

    genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);

    size_t taille_base64 = 0;

    //encodage de a cle
    char *base64 = uint8_to_base64(
        (const uint8_t *)&rsa_key.pubKey,
        sizeof(rsa_key.pubKey),
        &taille_base64
    );
   //decodage de la clé
   rsaKey_t nouvelle_cle;

    size_t taille_decodee = 0;

    uint8_t *decode = base64_to_uint8(
        base64,
        taille_base64,
        &taille_decodee
    );

    
    if (decode != NULL && taille_decodee == sizeof(nouvelle_cle))
    {
        memcpy(&nouvelle_cle, decode, sizeof(nouvelle_cle));
    }

    //Vérification des cléf
    printf("Clé chiffrer en base : %s\n", (char *) base64);
    printf("Cle initiale : ");
    printKeyHex(&rsa_key.pubKey);
    printf("Cle decodé : ");
    printKeyHex(&nouvelle_cle);

    free(base64);


}


int main(void)
{
    logfp = fopen("./logfp_test_2", "w");
    test_chiffrement_bloc();
    test_chiffrement_dechiffrement_fichier();
    test_base64(); 
    return 0;
}
