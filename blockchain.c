#include "bc_rsa.h"
#include "sha256_utils.h"

void calculer_merkle_root(Block *b) {
    // S'il n'y a pas de transactions dans le bloc racine =  zéro
    if (b == NULL || b->nbTx == 0) {
        memset(b->merkleTree, '0', HASHLENGTH - 1);
        b->merkleTree[HASHLENGTH - 1] = '\0';
        return;
    }

    // Calcul capacité maximale pour le tableau des hash 
    int max_nodes = 1;
    while (max_nodes < b->nbTx) {
        max_nodes *= 2;
    }
    
    // Tableaux pour stocker les hashs niveau par niveau
    char currentHashes[max_nodes][HASHLENGTH];
    int numHashes = 0;

   
    Slist *current = b->transactions;
    while (current != NULL) {
        Transaction *tx = (Transaction *)current->info;
        strncpy(currentHashes[numHashes], (char *)tx->txid, HASHLENGTH);
        numHashes++;
        current = current->next;
    }

    char nextHashes[max_nodes][HASHLENGTH];
    char concatBuffer[HASHLENGTH * 2]; // Tampon 

    // 2. Remontée de l'arbre jusqu'à ce qu'il ne reste qu'un seul hash
    while (numHashes > 1) {
        // Règle d'imparité : si le nombre de hashs est impair on duplique le dernier
        if (numHashes % 2 != 0) {
            strncpy(currentHashes[numHashes], currentHashes[numHashes - 1], HASHLENGTH);
            numHashes++;
        }

        int nextNumHashes = 0;
        
        // Hachage par paires
        for (int i = 0; i < numHashes; i += 2) {
            snprintf(concatBuffer, sizeof(concatBuffer), "%s%s", currentHashes[i], currentHashes[i+1]);
            sha256ofString((BYTE *)concatBuffer, nextHashes[nextNumHashes]);
            nextNumHashes++;
        }
        for (int i = 0; i < nextNumHashes; i++) {
            strncpy(currentHashes[i], nextHashes[i], HASHLENGTH);
        }
        numHashes = nextNumHashes;
    }

    // 3. dernier hash 
    strncpy((char *)b->merkleTree, currentHashes[0], HASHLENGTH);
}