#include "phase1.h"
#include <stdio.h>


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

    fprintf(f, "%lu  %lu\n", kp->pubKey.E, kp->pubKey.N);
    fprintf(f, "%lu  %lu\n", kp->privKey.E, kp->privKey.N);
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

    if(fscanf(f, "%lu  %lu\n", &kp->pubKey.E, &kp->pubKey.N ) != 2){
        fclose(f);
        return -1;
    }

    //load de la cle prive 
    if(fscanf(f, "%lu  %lu\n", &kp->privKey.E, &kp->privKey.N) != 2){
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}