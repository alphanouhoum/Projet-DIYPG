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
  printf("TEST sauvegardement et chargement de clé\n");
  keyPair_t  rsa_key, copy;
  genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);

  char *filename = "keys_log";

  saveKeys(filename, &rsa_key);
  loadKeys(filename, &copy);

  printKeyPairHex(&rsa_key);
  printKeyPairHex(&copy);



}

int test_utf8(int nb){
  keyPair_t rsa_key;
  char c = 'A';

  uint64_t message = (unsigned char)c; 
  for (int i = 0; i < nb; i++)
  {
    //convertie le caractere en   un caractere UTF8
    genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);
    printKeyPairHex(&rsa_key);
    uint64_t message_chiffre = puissance_mod_n(message, rsa_key.pubKey.E, rsa_key.pubKey.N);
    uint64_t message_dechiffre = puissance_mod_n(message_chiffre, rsa_key.privKey.E, rsa_key.privKey.N);

    printf("Original : %c\n", c);
    printf("Chiffre  : %llu\n", (unsigned long long)message_chiffre);
    printf("Dechiffre : %c\n", (char)message_dechiffre);

    if (message != message_dechiffre)
    {
      return -1;
    }
    
  }

  return 0;
}

int main(void) {
  logfp = fopen("./logfp", "w");
  srand(time(NULL));

  //test_affichage_hex();
  //test_save_and_load_key();

  int res = test_utf8(1000);
  
  printf(res == 0 ? "TEST utf8 OK\n" : "TEST UTF8 ECHEC\n");
  
  return 0;
}
