#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa_common_header.h"
#include "interpreter.h"
#include "phase2.h"
#include "phase1.h"
#include "sha256.h"

// Déclarations pour other_base64.c
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length);
unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length);

KeyDirectory directory = { .count = 0 };

//UTILITAIRE 
int find_key_index(char *id) {
    if (!id) return -1;
    for (int i = 0; i < directory.count; i++) {
        if (strcmp(directory.tab[i].id, id) == 0) return i;
    }
    return -1;
}

//COMMANDES PHASE 3
void cmd_newkeys(char *id, char *type) {
    if (!id || !type) { printf("Usage : newkeys <keyid> <type>\n"); return; }
    if (strcmp(type, "crypt") != 0 && strcmp(type, "sign") != 0) {
        printf("Erreur : le type doit être 'crypt' ou 'sign'.\n"); return;
    }
    if (directory.count >= MAX_KEYS) { printf("Erreur : annuaire plein.\n"); return; }
    if (find_key_index(id) != -1) { printf("Erreur : l'identifiant '%s' existe déjà.\n", id); return; }
    
    printf("Génération des clefs pour '%s' (%s)...\n", id, type);
    UserKey new_key;
    strncpy(new_key.id, id, MAX_STR_LEN);
    strncpy(new_key.type, type, MAX_STR_LEN);
    do
    {
        genKeysRabin(&new_key.keys.pubKey, &new_key.keys.privKey, MAX_PRIME); 
    } while (new_key.keys.pubKey.N <= UINT32_MAX);

    directory.tab[directory.count++] = new_key;
    printf("Clefs générées et ajoutées !\n");
}

void cmd_listkeys(char *id_opt) {
    if (directory.count == 0) { printf("L'annuaire est vide.\n"); return; }
    printf("--- Liste des clefs ---\n");
    for (int i = 0; i < directory.count; i++) {
        if (!id_opt || strcmp(directory.tab[i].id, id_opt) == 0) {
            printf("- %s [%s]\n", directory.tab[i].id, directory.tab[i].type);
        }
    }
}

void cmd_rmkeys(char *keyid) {
    int idx = find_key_index(keyid);
    if (idx == -1) { printf("Erreur : clef '%s' introuvable.\n", keyid ? keyid : "NULL"); return; }
    for (int i = idx; i < directory.count - 1; i++) {
        directory.tab[i] = directory.tab[i + 1];
    }
    directory.count--;
    printf("Succès : La clef '%s' a été supprimée.\n", keyid);
}

void cmd_show(char *keyid, char *f1, char *f2) {
    int idx = find_key_index(keyid);
    if (idx == -1) { printf("Erreur : clef '%s' introuvable.\n", keyid ? keyid : "NULL"); return; }
    
    int show_pub = (!f1 && !f2) || (f1 && strcmp(f1, "pub") == 0) || (f2 && strcmp(f2, "pub") == 0);
    int show_priv = (!f1 && !f2) || (f1 && strcmp(f1, "priv") == 0) || (f2 && strcmp(f2, "priv") == 0);

    printf("--- Clef '%s' [%s] ---\n", keyid, directory.tab[idx].type);
    if (show_pub) printf("Publique : E=0x%llx, N=0x%llx\n", (unsigned long long)directory.tab[idx].keys.pubKey.E, (unsigned long long)directory.tab[idx].keys.pubKey.N);
    if (show_priv) printf("Privée   : U=0x%llx, N=0x%llx\n", (unsigned long long)directory.tab[idx].keys.privKey.E, (unsigned long long)directory.tab[idx].keys.privKey.N);
}

void cmd_savepub(char *keyid, char *fileOut) {
    if (!keyid || !fileOut) { printf("Usage : savepub <keyid> <file>\n"); return; }
    int idx = find_key_index(keyid);
    if (idx == -1) { printf("Erreur : clef introuvable.\n"); return; }
    FILE *f = fopen(fileOut, "w");
    if (!f) { printf("Erreur : impossible de créer %s.\n", fileOut); return; }
    fprintf(f, "E= %llu\nN= %llu\n", (unsigned long long)directory.tab[idx].keys.pubKey.E, (unsigned long long)directory.tab[idx].keys.pubKey.N);
    fclose(f);
    printf("Clef publique exportée dans '%s'.\n", fileOut);
}

void cmd_save(char *filename) {
    char *target = filename ? filename : "annuaire.dat";
    FILE *f = fopen(target, "wb");
    if (!f) { printf("Erreur de sauvegarde.\n"); return; }
    fwrite(&directory.count, sizeof(int), 1, f);
    fwrite(directory.tab, sizeof(UserKey), directory.count, f);
    fclose(f);
    printf("Annuaire sauvegardé dans %s.\n", target);
}

void cmd_load(char *filename) {
    char *target = filename ? filename : "annuaire.dat";
    FILE *f = fopen(target, "rb");
    if (!f) { printf("Fichier %s introuvable.\n", target); return; }
    fread(&directory.count, sizeof(int), 1, f);
    fread(directory.tab, sizeof(UserKey), directory.count, f);
    fclose(f);
    printf("Annuaire chargé depuis %s.\n", target);
}

void cmd_crypt(char *fileIn, char *fileOut, char *keyid) {
    if (!fileIn || !fileOut || !keyid) { printf("Usage : crypt <fileIn> <fileOut> <keyid>\n"); return; }
    int idx = find_key_index(keyid);
    if (idx == -1 || strcmp(directory.tab[idx].type, "crypt") != 0) { printf("Erreur : clef '%s' introuvable ou non 'crypt'.\n", keyid); return; }
    int res = chiffrer_fichierV2(fileIn, fileOut, &directory.tab[idx].keys.pubKey);
    if (res == 0)
        printf("Chiffrement reussi.\n");
    else
        printf("Erreur lors du chiffrement.\n");
}

void cmd_uncrypt(char *fileIn, char *fileOut, char *keyid) {
    if (!fileIn || !fileOut || !keyid) { printf("Usage : uncrypt <fileIn> <fileOut> <keyid>\n"); return; }
    int idx = find_key_index(keyid);
    if (idx == -1 || strcmp(directory.tab[idx].type, "crypt") != 0) { printf("Erreur : clef '%s' introuvable ou non 'crypt'.\n", keyid); return; }
    int res = dechiffrer_fichierV2(fileIn, fileOut, &directory.tab[idx].keys.privKey);
    if (res == 0)
        printf("Déchhiffrement reussi.\n");
    else
        printf("Erreur lors du Déchhiffrement.\n");
}

void cmd_bin2b64(char *fileIn, char *fileOut) {
    if (!fileIn || !fileOut) { printf("Usage : bin-2b64 <filein> <fileout>\n"); return; }
    FILE *fin = fopen(fileIn, "rb");
    if (!fin) { printf("Erreur d'ouverture de %s\n", fileIn); return; }
    fseek(fin, 0, SEEK_END); size_t in_len = ftell(fin); fseek(fin, 0, SEEK_SET);
    unsigned char *in_buffer = malloc(in_len);
    fread(in_buffer, 1, in_len, fin); fclose(fin);
    
    size_t out_len = 0;
    char *encoded = base64_encode(in_buffer, in_len, &out_len);
    FILE *fout = fopen(fileOut, "w");
    if (fout && encoded) { fwrite(encoded, 1, out_len, fout); fclose(fout); printf("Succès : conversion Base64.\n"); }
    free(in_buffer); free(encoded);
}

void cmd_b642bin(char *fileIn, char *fileOut) {
    if (!fileIn || !fileOut) { printf("Usage : b64-2bin <filein> <fileout>\n"); return; }
    FILE *fin = fopen(fileIn, "rb");
    if (!fin) { printf("Erreur d'ouverture de %s\n", fileIn); return; }
    fseek(fin, 0, SEEK_END); size_t in_len = ftell(fin); fseek(fin, 0, SEEK_SET);
    char *in_buffer = malloc(in_len);
    fread(in_buffer, 1, in_len, fin); fclose(fin);
    
    size_t out_len = 0;
    unsigned char *decoded = base64_decode(in_buffer, in_len, &out_len);
    FILE *fout = fopen(fileOut, "wb");
    if (fout && decoded) { fwrite(decoded, 1, out_len, fout); fclose(fout); printf("Succès : décodage binaire.\n"); }
    free(in_buffer); free(decoded);
}

// --- PHASE 4 : SIGNATURE ET VÉRIFICATION ---
void cmd_sign(char *fileIn, char *signatureOut, char *keyid) {
    if (!fileIn || !signatureOut || !keyid) {
        printf("Usage : sign <fileIn> <signatureOut> <keyid>\n");
        return;
    }
    int idx = find_key_index(keyid);
    if (idx == -1) { printf("Erreur : clef '%s' introuvable.\n", keyid); return; }
    if (strcmp(directory.tab[idx].type, "sign") != 0) {
        printf("Erreur : la clef doit être de type 'sign' pour signer.\n");
        return;
    }

    FILE *fin = fopen(fileIn, "rb");
    if (!fin) { printf("Erreur d'ouverture du fichier %s\n", fileIn); return; }

    // 1. Calcul du SHA-256
    SHA256_CTX ctx;
    sha256_init(&ctx);
    BYTE buffer[1024];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), fin)) > 0) {
        sha256_update(&ctx, buffer, bytes);
    }
    fclose(fin);

    BYTE hash[SHA256_BLOCK_SIZE];
    sha256_final(&ctx, hash);

    // 2. Écrire le hash dans un fichier temporaire
    FILE *ftemp = fopen("temp_hash.bin", "wb");
    if (!ftemp) { printf("Erreur de création du fichier temporaire.\n"); return; }
    fwrite(hash, 1, SHA256_BLOCK_SIZE, ftemp);
    fclose(ftemp);

    // 3. Chiffrer ce fichier temporaire avec la clef PRIVÉE (fonctions V2 avec GMP !)
    int res = chiffrer_fichierV2("temp_hash.bin", signatureOut, &directory.tab[idx].keys.privKey);
    remove("temp_hash.bin"); // On supprime le fichier temporaire ni vu ni connu

    if (res == 0) {
        printf("Succès : Le fichier '%s' a été signé. Signature dans '%s'.\n", fileIn, signatureOut);
    } else {
        printf("Erreur lors de la création de la signature.\n");
    }
}

void cmd_verify(char *fileIn, char *signatureIn, char *keyid) {
    if (!fileIn || !signatureIn || !keyid) {
        printf("Usage : verify <fileIn> <signatureIn> <keyid>\n");
        return;
    }
    int idx = find_key_index(keyid);
    if (idx == -1) { printf("Erreur : clef '%s' introuvable.\n", keyid); return; }
    if (strcmp(directory.tab[idx].type, "sign") != 0) {
        printf("Erreur : la clef doit être de type 'sign' pour vérifier.\n");
        return;
    }

    // 1. Recalcul du SHA-256 du fichier en l'état actuel
    FILE *fin = fopen(fileIn, "rb");
    if (!fin) { printf("Erreur d'ouverture du fichier %s\n", fileIn); return; }

    SHA256_CTX ctx;
    sha256_init(&ctx);
    BYTE buffer[1024];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), fin)) > 0) {
        sha256_update(&ctx, buffer, bytes);
    }
    fclose(fin);

    BYTE hash_computed[SHA256_BLOCK_SIZE];
    sha256_final(&ctx, hash_computed);

    // 2. Déchiffrement de la signature avec la clef PUBLIQUE (fonctions V2 avec GMP !)
    int res = dechiffrer_fichierV2(signatureIn, "temp_hash_dec.bin", &directory.tab[idx].keys.pubKey);
    if (res != 0) {
        printf("Erreur lors du déchiffrement de la signature.\n");
        remove("temp_hash_dec.bin");
        return;
    }

    // 3. Lire l'empreinte qui a été déchiffrée
    FILE *ftemp = fopen("temp_hash_dec.bin", "rb");
    if (!ftemp) { printf("Erreur de lecture de la signature déchiffrée.\n"); return; }
    BYTE hash_decrypted[SHA256_BLOCK_SIZE] = {0};
    fread(hash_decrypted, 1, SHA256_BLOCK_SIZE, ftemp);
    fclose(ftemp);
    remove("temp_hash_dec.bin"); // Nettoyage

    // 4. Comparaison stricte
    if (memcmp(hash_computed, hash_decrypted, SHA256_BLOCK_SIZE) == 0) {
        printf(">>> [VALIDE] La signature correspond. Le fichier est authentique et intact.\n");
    } else {
        printf(">>> [INVALIDE] ALERTE ! La signature ne correspond pas.\n");
    }
}

void afficher_aide(void) {
    printf("\n========== COMMANDES DISPONIBLES ==========\n");
    printf("newkeys <id> <type>        : Generer une paire de cles (type: crypt ou sign)\n");
    printf("listkeys [id]              : Lister les cles\n");
    printf("show <id> [pub|priv]       : Afficher une cle\n");
    printf("rmkeys <id>                : Supprimer une cle\n");
    printf("savepub <id> <fichier>     : Exporter une cle publique\n");
    printf("crypt <entree> <sortie> <id>   : Chiffrer un fichier\n");
    printf("uncrypt <entree> <sortie> <id> : Dechiffrer un fichier\n");
    printf("sign <entree> <sortie> <id>    : Signer un fichier\n");
    printf("verify <entree> <sig> <id>     : Verifier une signature\n");
    printf("bin-2b64 <entree> <sortie> : Convertir en Base64\n");
    printf("b64-2bin <entree> <sortie> : Convertir en binaire\n");
    printf("save [fichier]             : Sauvegarder l'annuaire\n");
    printf("load [fichier]             : Charger l'annuaire\n");
    printf("help                       : Afficher cette aide\n");
    printf("quit                       : Quitter\n");
    printf("==========================================\n\n");
}

void start_interpreter() {
    char input[256];
    const char *delim = " \t\r\n";
    printf("Bienvenue dans DIYPG (Phase 3 & 4). Tapez 'quit' pour quitter.\n");
    afficher_aide();
    while (1) {
        printf("DIYPG> ");
        if (!fgets(input, sizeof(input), stdin)) break;
        
        char *cmd = strtok(input, delim);
        if (!cmd) continue;

        if (strcmp(cmd, "quit") == 0) break;
        else if (strcmp(cmd, "newkeys") == 0) { char *id = strtok(NULL, delim); char *type = strtok(NULL, delim); cmd_newkeys(id, type); }
        else if (strcmp(cmd, "listkeys") == 0) { char *id = strtok(NULL, delim); cmd_listkeys(id); }
        else if (strcmp(cmd, "rmkeys") == 0) { char *id = strtok(NULL, delim); cmd_rmkeys(id); }
        else if (strcmp(cmd, "show") == 0) { char *id = strtok(NULL, delim); char *f1 = strtok(NULL, delim); char *f2 = strtok(NULL, delim); if (!id) printf("Usage : show <keyid> [\"pub\"] [\"priv\"]\n"); else cmd_show(id, f1, f2); }
        else if (strcmp(cmd, "savepub") == 0) { char *id = strtok(NULL, delim); char *fout = strtok(NULL, delim); cmd_savepub(id, fout); }
        else if (strcmp(cmd, "save") == 0) { char *fout = strtok(NULL, delim); cmd_save(fout); }
        else if (strcmp(cmd, "load") == 0) { char *fin = strtok(NULL, delim); cmd_load(fin); }
        else if (strcmp(cmd, "crypt") == 0) { char *fin = strtok(NULL, delim); char *fout = strtok(NULL, delim); char *id = strtok(NULL, delim); cmd_crypt(fin, fout, id); }
        else if (strcmp(cmd, "uncrypt") == 0) { char *fin = strtok(NULL, delim); char *fout = strtok(NULL, delim); char *id = strtok(NULL, delim); cmd_uncrypt(fin, fout, id); }
        else if (strcmp(cmd, "bin-2b64") == 0) { char *fin = strtok(NULL, delim); char *fout = strtok(NULL, delim); cmd_bin2b64(fin, fout); }
        else if (strcmp(cmd, "b64-2bin") == 0) { char *fin = strtok(NULL, delim); char *fout = strtok(NULL, delim); cmd_b642bin(fin, fout); }
        else if (strcmp(cmd, "sign") == 0) { char *fin = strtok(NULL, delim); char *fout = strtok(NULL, delim); char *id = strtok(NULL, delim); cmd_sign(fin, fout, id); }
        else if (strcmp(cmd, "verify") == 0) { char *fin = strtok(NULL, delim); char *fout = strtok(NULL, delim); char *id = strtok(NULL, delim); cmd_verify(fin, fout, id); }
        else if (strcmp(cmd, "help") == 0) afficher_aide();
        else printf("Commande inconnue : %s\n", cmd);
    }
}