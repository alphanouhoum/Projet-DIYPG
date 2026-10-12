#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rsa_common_header.h"
#include "phase1.h"

FILE *logfp;

void test_affichage_hex(){
  printf("TEST affichage clé HEXADECIMAL\n");
  keyPair_t rsa_key;
  genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);
  printKeyPairHex(&rsa_key);
}

void test_save_and_load_key(){
  printf("\n\nTEST sauvegardement et chargement de clé\n");

  keyPair_t  rsa_key, copy;
  genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);

  char *filename = "keys_log";

  saveKeys(filename, &rsa_key);
  loadKeys(filename, &copy);

  printKeyPairHex(&rsa_key);
  printf("Clés retirer du fichier : \n");
  printKeyPairHex(&copy);
}

void test_utf8(int nb_test){
  printf("\n\nTEST chiffrement et déchiffrement caractère UTF8\n");

  int nb_echec = 0;

  keyPair_t rsa_key;
  char c = 'A';
  
  uint64_t message = (unsigned char)c; //convertie le caractere en un caractere UTF8
  for (int i = 0; i < nb_test; i++)
  {
    
    genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);
    uint64_t message_chiffre = puissance_mod_n(message, rsa_key.pubKey.E, rsa_key.pubKey.N);
    uint64_t message_dechiffre = puissance_mod_n(message_chiffre, rsa_key.privKey.E, rsa_key.privKey.N);

    if (message != message_dechiffre)
    {
      nb_echec ++;
    }
  }

  printf("MAX_PRIME = %d Nb Test = %d, Test echouer = %d\n", MAX_PRIME, nb_test, nb_echec);
}

void test_chiffrement_dechiffrement_tab_octet(){
  printf("\n\nTEST chiffrement et déchiffrement tableau d'octets\n");

  keyPair_t rsa_key;
  genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);

  uint8_t message[] = "AAAA";
  size_t taille = sizeof(message) - 1;

  printf("Message original : %s\n", message);
 
  printf("Taille originale : %zu octets\n", taille);

  uint8_t * message_chifffrer= chiffrer_tab_octet(message, taille, &rsa_key.pubKey);
  if (message_chifffrer == NULL)
  {
    printf("Erreur de chiffrement");
    return;
  }
  printf("Chiffré (hexa)   : ");
  for (size_t i = 0; i < taille * NB_OCTETS_CHIFFRE; i++)
    printf("%02X ", message_chifffrer[i]);
  printf("\n");
  
  //dechiffrage du message chiffrer


  uint8_t *message_dechiffrer = dechiffrer_tab_octet(message_chifffrer, taille* NB_OCTETS_CHIFFRE, &rsa_key.privKey);

  if (message_dechiffrer == NULL)
  {
    printf("Erreur de déchiffrement");
    return;
  }

   
  printf("Message dechiffrer %s\n", (char *)message_dechiffrer);

  if (memcmp(message_dechiffrer, message, taille)==0) //compare le taille premier octect pointer par message_dechiffrer et message
  {
    printf("TEST Ok\n");
  }else{
    printf("TEST ECHEC\n");
  }
  

  free(message_chifffrer);
  free(message_dechiffrer);

}

void test_chiffrement_dechiffrement_fichier(){
  printf("\n\nTEST chiffrement et déchiffrement fichier\n");


  keyPair_t rsa_key;
  genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);

  char * fichier_entrer = "./message";
  char * fichier_sortie = "message_chiffrer";
  char * fichier_dechiffre = "fichier_dechiffre";


  int res = chiffrer_fichier(fichier_entrer, fichier_sortie, &rsa_key.pubKey);

  printf(res == 0 ? "TEST OK Chiffrement\n" : "TEST Echec Chiffrement\n");

  //dechiffrement du fichier 
  res = dechiffrer_fichier(fichier_sortie, fichier_dechiffre, &rsa_key.privKey);

  printf(res == 0 ? "TEST OK Dechiffrement\n" : "TEST Echec Dechiffrement\n");


}

int main(void) {
  logfp = fopen("./logfp", "w");
  srand(time(NULL));

  test_affichage_hex();
  test_save_and_load_key();

  test_utf8(100);
  
  test_chiffrement_dechiffrement_tab_octet();
  
  test_chiffrement_dechiffrement_fichier();
  return 0;
}
