#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa_common_header.h"
#include "interpreter.h"
#include "phase2.h"
#include "phase1.h"

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
    genKeysRabin(&new_key.keys.pubKey, &new_key.keys.privKey, MAX_PRIME); 
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
    fprintf(f, "%llu\n%llu\n", (unsigned long long)directory.tab[idx].keys.pubKey.E, (unsigned long long)directory.tab[idx].keys.pubKey.N);
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

void cmd_bin2664(char *fileIn, char *fileOut) {
    if (!fileIn || !fileOut) { printf("Usage : bin-2664 <filein> <fileout>\n"); return; }
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

void cmd_6642bin(char *fileIn, char *fileOut) {
    if (!fileIn || !fileOut) { printf("Usage : 664-2bin <filein> <fileout>\n"); return; }
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

//BOUCLE PRINCIPALE DE L'INTERPRÈTE 
void afficher_aide(void)
{
    printf("\n========== COMMANDES DISPONIBLES ==========\n");
    printf("newkeys <id> <type>       : Generer une paire de cles\n");
    printf("listkeys [id]             : Lister les cles\n");
    printf("show <id> [pub|priv]      : Afficher une cle\n");
    printf("rmkeys <id>               : Supprimer une cle\n");
    printf("savepub <id> <fichier>    : Exporter une cle publique\n");
    printf("crypt <entree> <sortie> <id>   : Chiffrer un fichier\n");
    printf("uncrypt <entree> <sortie> <id> : Dechiffrer un fichier\n");
    printf("bin-2664 <entree> <sortie> : Convertir en Base64\n");
    printf("664-2bin <entree> <sortie> : Convertir en binaire\n");
    printf("save [fichier]            : Sauvegarder l'annuaire\n");
    printf("load [fichier]            : Charger l'annuaire\n");
    printf("help                      : Afficher cette aide\n");
    printf("quit                      : Quitter\n");
    printf("==========================================\n\n");
}

void start_interpreter() {
    char input[256];
    const char *delim = " \t\r\n";
    printf("Bienvenue dans DIYPG (Phase 3). Tapez 'quit' pour quitter.\n");
    afficher_aide();
    while (1) {
        printf("DIYPG> ");
        if (!fgets(input, sizeof(input), stdin)) break;
        
        char *cmd = strtok(input, delim);
        if (!cmd) continue;

        if (strcmp(cmd, "quit") == 0) break;
        else if (strcmp(cmd, "newkeys") == 0) {
            char *id = strtok(NULL, delim);
            char *type = strtok(NULL, delim);
            cmd_newkeys(id, type);
        }
        else if (strcmp(cmd, "listkeys") == 0) {
            char *id = strtok(NULL, delim);
            cmd_listkeys(id);
        }
        else if (strcmp(cmd, "rmkeys") == 0) {
            char *id = strtok(NULL, delim);
            cmd_rmkeys(id);
        }
        else if (strcmp(cmd, "show") == 0) {
            char *id = strtok(NULL, delim);
            char *f1 = strtok(NULL, delim);
            char *f2 = strtok(NULL, delim);
            if (!id) printf("Usage : show <keyid> [\"pub\"] [\"priv\"]\n");
            else cmd_show(id, f1, f2);
        }
        else if (strcmp(cmd, "savepub") == 0) {
            char *id = strtok(NULL, delim);
            char *fout = strtok(NULL, delim);
            cmd_savepub(id, fout);
        }
        else if (strcmp(cmd, "save") == 0) {
            char *fout = strtok(NULL, delim);
            cmd_save(fout);
        }
        else if (strcmp(cmd, "load") == 0) {
            char *fin = strtok(NULL, delim);
            cmd_load(fin);
        }
        else if (strcmp(cmd, "crypt") == 0) {
            char *fin = strtok(NULL, delim);
            char *fout = strtok(NULL, delim);
            char *id = strtok(NULL, delim);
            cmd_crypt(fin, fout, id);
        }
        else if (strcmp(cmd, "uncrypt") == 0) {
            char *fin = strtok(NULL, delim);
            char *fout = strtok(NULL, delim);
            char *id = strtok(NULL, delim);
            cmd_uncrypt(fin, fout, id);
        }
        else if (strcmp(cmd, "bin-2664") == 0) {
            char *fin = strtok(NULL, delim);
            char *fout = strtok(NULL, delim);
            cmd_bin2664(fin, fout);
        }
        else if (strcmp(cmd, "664-2bin") == 0) {
            char *fin = strtok(NULL, delim);
            char *fout = strtok(NULL, delim);
            cmd_6642bin(fin, fout);
        }
        else if (strcmp(cmd, "help") == 0) {
            afficher_aide();
        }
        else {
            printf("Commande inconnue : %s\n", cmd);
        }
    }
}