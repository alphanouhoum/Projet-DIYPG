#include "rsa_common_header.h"
#include "phase1.h"

FILE *logfp;

int main(void)
{
  logfp = stdout;
  srand(time(NULL));

  rsaKey_t pub, priv;
  genKeysRabin(&pub, &priv, MAX_PRIME);

  uint64_t message = 42;
  uint64_t chiffre = puissance_mod_n(message, pub.E, pub.N);
  uint64_t clair = puissance_mod_n(chiffre, priv.E, priv.N);

  printf("message = %llu\nchiffré = %llu\ndéchiffré = %llu\n",
         (unsigned long long)message, (unsigned long long)chiffre, (unsigned long long)clair);
  printf(clair == message ? "TEST OK\n" : "TEST ECHEC\n");
  return 0;
}

void afficher_cle(const char *nom, const rsaKey_t *cle)
{
  printf("%s : (0x%llx, 0x%llx)\n", nom, (unsigned long long)cle->E, (unsigned long long)cle->N);
}

int sauver_cles(const char *fichier, const keyPair_t *kp)
{
  FILE *f = fopen(fichier, "w");
  if (!f)
  {
    printf("Erreur a l'ouverture de %s en ecriture\n", fichier);
    return 0;
  }
  fprintf(f, "%llx %llx\n", (unsigned long long)kp->pubKey.E, (unsigned long long)kp->pubKey.N);
  fprintf(f, "%llx %llx\n", (unsigned long long)kp->privKey.E, (unsigned long long)kp->privKey.N);
  fclose(f);
  return 1;
}

int charger_cles(const char *fichier, keyPair_t *kp)
{
  FILE *f = fopen(fichier, "r");
  if (!f)
  {
    printf("Erreur a l'ouverture de %s en lecture\n", fichier);
    return 0;
  }
  unsigned long long e_pub, n_pub, e_priv, n_priv;
  if (fscanf(f, "%llx %llx", &e_pub, &n_pub) != 2 ||
      fscanf(f, "%llx %llx", &e_priv, &n_priv) != 2)
  {
    fclose(f);
    return 0;
  }
  kp->pubKey.E = e_pub;
  kp->pubKey.N = n_pub;
  kp->privKey.E = e_priv;
  kp->privKey.N = n_priv;
  fclose(f);
  return 1;
}
