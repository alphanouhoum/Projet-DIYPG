#include "rsa_common_header.h"
#include "phase1.h"

FILE *logfp;

int main(void) {
  logfp = stdout;
  srand(time(NULL));

  rsaKey_t pub, priv;
  genKeysRabin(&pub, &priv, MAX_PRIME);

  uint64_t message = 42;
  uint64_t chiffre = puissance_mod_n(message, pub.E, pub.N);
  uint64_t clair   = puissance_mod_n(chiffre, priv.E, priv.N);

  printf("message = %llu\nchiffré = %llu\ndéchiffré = %llu\n",
         (unsigned long)message, (unsigned long)chiffre, (unsigned long)clair);
  printf(clair == message ? "TEST OK\n" : "TEST ECHEC\n");
  return 0;
}