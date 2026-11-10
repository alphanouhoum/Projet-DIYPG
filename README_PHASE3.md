## Équipe du projet

**Groupe n° 8**

Ce projet est réalisé par les membres suivants :

- **Alpha Nouhoum TOURE**
- **Yanis AHAQAR**
- **Ifaz Abrar ULLAH**
- **Johan NZENGUE MOMO**

# Phase 3 — Interprète de commande et annuaire de clefs

## 1. Objectif

Cette troisième phase du projet consiste à développer un interpréteur en ligne de commande permettant de manipuler des paires de clés cryptographiques et d'effectuer différentes opérations sur des fichiers.

L'interpréteur permet notamment de :
- Générer des paires de clés cryptographiques.
- Gérer un annuaire de clés à l'aide d'identifiants.
- Afficher et supprimer des clés.
- Exporter des clés publiques.
- Chiffrer et déchiffrer des fichiers.
- Convertir des fichiers binaires en Base64 et inversement.
- Sauvegarder et charger l'annuaire de clés.

## 2. Prérequis

Pour compiler et exécuter le projet, les outils suivants sont nécessaires :

- GCC (compilateur C).
- GNU Make.
- Bibliothèque GMP (GNU Multiple Precision Arithmetic Library).

Sous Linux, les dépendances peuvent être installées avec :

```bash
sudo apt update
sudo apt install build-essential libgmp-dev
```

## 3. Compilation et exécution

Depuis le répertoire racine du projet, compiler avec :

```bash
make
```

Pour lancer l'interpréteur :

```bash
./main
```

Pour supprimer les fichiers objets et l'exécutable :

```bash
make mrproper
```

Au démarrage, l'interpréteur affiche une invite de commande :

```text
DIYPG>
```

La commande `help` permet d'afficher les commandes disponibles.

## 4. Commandes disponibles

### Gestion des clés

| Commande | Description |
|---|---|
| `newkeys <id> <type>` | Génère une paire de clés associée à un identifiant. |
| `listkeys` | Affiche toutes les clés présentes dans l'annuaire. |
| `listkeys <id>` | Affiche une clé précise. |
| `show <id>` | Affiche les informations d'une paire de clés. |
| `rmkeys <id>` | Supprime une clé de l'annuaire. |
| `savepub <id> <fichier>` | Exporte la clé publique dans un fichier. |

Les types de clés acceptés sont :
- `crypt` : clé destinée au chiffrement et au déchiffrement.
- `sign` : clé destinée à la signature.

### Chiffrement et déchiffrement

| Commande | Description |
|---|---|
| `crypt <entrée> <sortie> <id>` | Chiffre un fichier avec la clé publique associée à l'identifiant. |
| `uncrypt <entrée> <sortie> <id>` | Déchiffre un fichier avec la clé privée associée à l'identifiant. |

Les fichiers sont manipulés en mode binaire afin de permettre le traitement de différents formats (TXT, JPG, PNG, etc.).

### Conversion Base64

| Commande | Description |
|---|---|
| `bin-2b64 <entrée> <sortie>` | Convertit un fichier binaire en Base64. |
| `b64-2bin <entrée> <sortie>` | Convertit un fichier Base64 en binaire. |

### Sauvegarde et chargement

| Commande | Description |
|---|---|
| `save` | Sauvegarde l'annuaire de clés. |
| `load` | Charge un annuaire précédemment sauvegardé. |

### Autres commandes

| Commande | Description |
|---|---|
| `help` | Affiche l'aide. |
| `quit` | Quitte l'interpréteur. |

## 5. Exemple d'utilisation

### Génération de clés

```text
DIYPG> newkeys alice crypt
DIYPG> listkeys
DIYPG> show alice
```

### Chiffrement et déchiffrement d'un fichier

Créer un fichier de test :

```bash
echo "Bonjour, ceci est un test !" > message.txt
```

Dans l'interpréteur :

```text
DIYPG> crypt message.txt message_chiffre alice
DIYPG> uncrypt message_chiffre message_dechiffre alice
```

Comparer ensuite les fichiers :

```bash
cmp message.txt message_dechiffre
```

Si aucune différence n'est affichée, le déchiffrement a correctement restitué le fichier original.

### Conversion Base64

```text
DIYPG> bin-2b64 message.txt message_base64.txt
DIYPG> b64-2bin message_base64.txt message_decode.txt
```

Vérifier le résultat :

```bash
cmp message.txt message_decode.txt
```

### Sauvegarde et chargement

```text
DIYPG> save 
DIYPG> rmkeys alice
DIYPG> load 
DIYPG> listkeys
```

Cette séquence permet de vérifier que l'annuaire peut être sauvegardé puis restauré.

