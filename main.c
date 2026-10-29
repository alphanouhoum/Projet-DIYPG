#include <stdint.h>
#include <stdio.h>
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

  keyPair_t rsa_key, copy;
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

  uint64_t message = (unsigned char)c; // convertie le caractere en un caractere UTF8
  for (int i = 0; i < nb_test; i++)
  {

    genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);
    uint64_t message_chiffre = puissance_mod_n(message, rsa_key.pubKey.E, rsa_key.pubKey.N);
    uint64_t message_dechiffre = puissance_mod_n(message_chiffre, rsa_key.privKey.E, rsa_key.privKey.N);

    if (message != message_dechiffre)
    {
      nb_echec++;
    }
  }

  printf("MAX_PRIME = %d Nb Test = %d, Test echouer = %d\n", MAX_PRIME, nb_test, nb_echec);
}

void test_chiffrement_dechiffrement_tab_octet(){
  printf("\n\nTEST chiffrement et déchiffrement tableau d'octets\n");

  keyPair_t rsa_key;
  genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);

  uint8_t message[] = "Test";
  size_t taille = sizeof(message) - 1;

  printf("Message original : %s\n", message);

  printf("Taille originale : %zu octets\n", taille);

  uint8_t *message_chifffrer = chiffrer_tab_octet(message, taille, &rsa_key.pubKey);
  if (message_chifffrer == NULL)
  {
    printf("Erreur de chiffrement");
    return;
  }
  printf("Chiffré (hexa)   : ");
  for (size_t i = 0; i < taille * NB_OCTETS_CHIFFRE; i++)
    printf("%02X ", message_chifffrer[i]);
  printf("\n");

  // dechiffrage du message chiffrer

  uint8_t *message_dechiffrer = dechiffrer_tab_octet(message_chifffrer, taille * NB_OCTETS_CHIFFRE, &rsa_key.privKey);

  if (message_dechiffrer == NULL)
  {
    printf("Erreur de déchiffrement");
    return;
  }

  printf("Message dechiffrer : %s\n", (char *)message_dechiffrer);

  if (memcmp(message_dechiffrer, message, taille) == 0) // compare le taille premier octect pointer par message_dechiffrer et message
  {
    printf("TEST Ok\n");
  }
  else
  {
    printf("TEST ECHEC\n");
  }

  free(message_chifffrer);
  free(message_dechiffrer);
}

void test_chiffrement_dechiffrement_fichier(){
  printf("\n\nTEST chiffrement et déchiffrement fichier\n");

  keyPair_t rsa_key;
  genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);

  char *fichier_entrer = "./message";
  char *fichier_sortie = "message_chiffrer";
  char *fichier_dechiffre = "message_dechiffre";

  int res = chiffrer_fichier(fichier_entrer, fichier_sortie, &rsa_key.pubKey);

  printf(res == 0 ? "TEST OK Chiffrement\n" : "TEST Echec Chiffrement\n");

  // dechiffrement du fichier
  res = dechiffrer_fichier(fichier_sortie, fichier_dechiffre, &rsa_key.privKey);

  printf(res == 0 ? "TEST OK Dechiffrement\n" : "TEST Echec Dechiffrement\n");
}

int test_conversion_base64(const char *nom, const void *donnee, size_t taille)
{
  size_t taille_base64 = 0;
  size_t taille_decodee = 0;

  /* Encodage en Base64 */
  char *base64 = uint8_to_base64(
      (const uint8_t *)donnee,
      taille,
      &taille_base64);

  if (base64 == NULL)
  {
    printf("[ECHEC] %s : erreur d'encodage.\n", nom);
    return 0;
  }

  /* Décodage du Base64 */
  uint8_t *decode = base64_to_uint8(
      base64,
      taille_base64,
      &taille_decodee);

  if (decode == NULL)
  {
    printf("[ECHEC] %s : erreur de decodage.\n", nom);
    free(base64);
    return 0;
  }

  /* Affichage */
  printf("\n========== %s ==========\n", nom);

  printf("Message original (hex) : ");
  const uint8_t *octets = (const uint8_t *)donnee;

  for (size_t i = 0; i < taille; i++)
    printf("%02X ", octets[i]); 

  printf("\nMessage Base64        : %s\n", base64);

  printf("Message decode (hex)  : ");
  for (size_t i = 0; i < taille_decodee; i++)
    printf("%02X ", decode[i]);

  printf("\n");

  /* Comparaison des données */
  int reussi = (taille == taille_decodee) && (memcmp(donnee, decode, taille) == 0);

  if (reussi)
    printf("[REUSSI] %s\n", nom);
  else
    printf("[ECHEC] %s : donnees differentes.\n", nom);

  free(base64);
  free(decode);

  return reussi;
}

void test_base64_uint32(void)
{
  uint32_t valeur = 123456;

  test_conversion_base64(
      "Test Conversion uint32_t",
      &valeur,
      sizeof(valeur));
}

void test_base64_uint64(void)
{
  uint64_t valeur = 1234567890123456789ULL;

  test_conversion_base64(
      "Conversion uint64_t",
      &valeur,
      sizeof(valeur));
}

void test_base64_caracteres(void)
{
  const char message[] = "Groupe 8";

  test_conversion_base64(
      "Conversion tableau de caracteres",
      message,
      strlen(message));
}

void test_base64_cles(void)
{
  keyPair_t rsa_key;

  genKeysRabin(&rsa_key.pubKey, &rsa_key.privKey, MAX_PRIME);
  test_conversion_base64(
      "Conversion de cles RSA",
      &rsa_key,
      sizeof(rsa_key));
}

void test_phase13_base64(void)
{
  printf("\n===== TESTS BASE64 : PHASE 1.3 =====\n");

  test_base64_uint32();
  test_base64_uint64();
  test_base64_caracteres();
  test_base64_cles();

}

void test_fichiers_base64(void)
{
  const char *fichier_original = "image.jpg";
  const char *fichier_base64 = "image_base64.txt";
  const char *fichier_decode = "image_decode.jpg";

  printf("\n===== TEST CONVERSION DE FICHIERS BASE64 =====\n");

  /* Encodage du fichier binaire en Base64 */
  if (fichier_binaire_vers_base64(fichier_original, fichier_base64) != 0)
  {
    printf("[ECHEC] Encodage du fichier.\n");
    return;
  }

  printf("[REUSSI] Fichier encode : %s -> %s\n", fichier_original, fichier_base64);

  /* Décodage du fichier Base64 en binaire */
  if (fichier_base64_vers_binaire(fichier_base64, fichier_decode) != 0)
  {
    printf("[ECHEC] Decodage du fichier.\n");
    return;
  }

  printf("[REUSSI] Fichier decode : %s -> %s\n", fichier_base64, fichier_decode);

}

int main(void)
{
  logfp = fopen("./logfp", "w");
  srand(time(NULL));

  test_affichage_hex();
  test_save_and_load_key();

  test_utf8(100);

  test_chiffrement_dechiffrement_tab_octet();

  test_chiffrement_dechiffrement_fichier();

  test_phase13_base64();

  test_fichiers_base64();
  printf("===== FIN DES TEST =====\n");

  return 0;
}
