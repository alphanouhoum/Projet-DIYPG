#include <stdio.h>
#include <stdint.h>

#include "phase1.h"
#include "phase2.h"
#include "rsa_common_header.h"

FILE *logfp;

void test_chiffrement_bloc(){

    printf("Test Chiffrage par boc\n");
    uint8_t msg[] = "Test niveau 2 !";
    printf("Message de test -> %s\n", msg);
    keyPair_t rsa_key;
    genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);

    printKeyPairHex(&rsa_key);

    size_t taille_msg =  sizeof(msg)-1;

    tab_bloc_t info_blocs;

    chiffrer_tab_octetV2(msg, taille_msg, &rsa_key.pubKey, &info_blocs);

    //DECHIFFREMENT
    printf("\nDechiffrement par bloc\n\n");

    uint8_t *res_dechiffrer = dechiffrer_tab_octetV2(&info_blocs, &rsa_key.privKey); 
    
    printf("Message dechiffrer : %s\n", (char *) res_dechiffrer);

    free(info_blocs.res_blocs);


}

void test_chiffrement_dechiffrement_fichier(){
  printf("\n\nTEST chiffrement et déchiffrement fichier\n");

  keyPair_t rsa_key;
  genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);

  char *fichier_entrer = "./message";
  char *fichier_sortie = "message_chiffrer";
  char *fichier_dechiffre = "message_dechiffre";

  tab_bloc_t info_chiffrer;
  int res = chiffrer_fichierV2(fichier_entrer, fichier_sortie, &rsa_key.pubKey, &info_chiffrer);

  printf(res == 0 ? "TEST OK Chiffrement\n" : "TEST Echec Chiffrement\n");

  // dechiffrement du fichier
  res = dechiffrer_fichierV2(fichier_sortie, fichier_dechiffre, &rsa_key.privKey, &info_chiffrer);

  printf(res == 0 ? "TEST OK Dechiffrement\n" : "TEST Echec Dechiffrement\n");
}

int main(void)
{
    logfp = fopen("./logfp_test_2", "w");
    test_chiffrement_bloc();
    test_chiffrement_dechiffrement_fichier();
    return 0;
}
