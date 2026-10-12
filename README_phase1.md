# Phase 1.0 — Implémentation et tests du chiffrement RSA

## 1. Objectif

L'objectif de cette phase est de comprendre le fonctionnement du code existant et d'implémenter les fonctionnalités nécessaires à la génération, à l'affichage, à la sauvegarde et au chargement des paires de clés RSA.

Des tests sont également réalisés pour vérifier le chiffrement et le déchiffrement d'un caractère, ainsi que pour étudier les limites liées à la capacité des entiers `uint64_t`.

## 2. Fonctionnalités implémentées

### 2.1. Affichage des clés en hexadécimal

Deux fonctions ont été implémentées :

- `printKeyHex()` : affiche une clé RSA en hexadécimal, avec les paramètres `E` et `N`.
- `printKeyPairHex()` : affiche successivement la clé publique et la clé privée.

### 2.2. Génération et affichage d'une paire de clés

La fonction `test_affichage_hex()` génère une paire de clés avec `genKeysRabin()`, en utilisant la constante `MAX_PRIME`, puis affiche les deux clés en hexadécimal.

### 2.3. Sauvegarde et chargement des clés

Deux fonctions ont été implémentées :

- `saveKeys()` : sauvegarde les paramètres `E` et `N` des clés publique et privée dans un fichier.
- `loadKeys()` : charge les paramètres des deux clés depuis un fichier.

La fonction `test_save_and_load_key()` génère une paire de clés, la sauvegarde dans le fichier `keys_log`, puis charge les valeurs dans une nouvelle structure.


### 2.4. Chiffrement et déchiffrement d'un caractère

La fonction `test_utf8()` teste le chiffrement et le déchiffrement du caractère `'A'`.

Le caractère est converti en une valeur numérique, puis chiffré avec la clé publique et déchiffré avec la clé privée.

Le résultat obtenu est comparé au message original. Si les deux valeurs diffèrent, le nombre d'échecs est incrémenté.

Le test est répété 100 fois par défaut, avec une nouvelle paire de clés générée à chaque itération.

## 3. Étude de la constante MAX_PRIME

L'objectif est d'étudier l'influence de la constante MAX_PRIME
sur la génération des clés et sur le bon fonctionnement du
chiffrement et du déchiffrement.

Un entier uint64_t peut représenter une valeur comprise entre
0 et 2^64.

## Résultats des tests

### Test 1 : MAX_PRIME = 100
- **Nombre de tests :** 100
- **Nombre d'échecs :** NA
- **Observations :** La valeur de `MAX_PRIME` est trop faible, ce qui peut entraîner la génération de clés identiques. Cela limite la fiabilité des tests.

### Test 2 : MAX_PRIME = 1 000
- **Nombre de tests :** 100
- **Nombre d'échecs :** 0
- **Observations :** Aucun échec n'a été observé. Les calculs restent dans une plage permettant au programme de fonctionner correctement.

### Test 3 : MAX_PRIME = 10 000
- **Nombre de tests :** 100
- **Nombre d'échecs :** entre 0 et 2
- **Observations :** Quelques échecs apparaissent. Ils sont dus aux dépassements de capacité lors des calculs arithmétiques sur les entiers `uint64_t`.

### Test 4 : MAX_PRIME = 100 000
- **Nombre de tests :** 100
- **Nombre d'échecs :** entre 10 et 24
- **Observations :** Les dépassements de capacité deviennent plus fréquents lorsque les valeurs utilisées dans les calculs augmentent, ce qui entraîne davantage d'échecs de déchiffrement.

### Test 5 : MAX_PRIME = 1 000 000
- **Nombre de tests :** 100
- **Nombre d'échecs :** entre 90 et 100
- **Observations :** Les dépassements de capacité perturbent fortement les calculs, ce qui provoque l'échec de la majorité des tests de chiffrement et de déchiffrement.

## Bilan expérimental

Les résultats montrent que l'augmentation de `MAX_PRIME` entraîne une hausse du nombre d'échecs.

Cette hausse s'explique par les dépassements de capacité des entiers non signés de 64 bits (`uint64_t`). Lors du calcul de la puissance modulaire, certaines multiplications (a*a) dépassent la valeur maximale représentable par ce type, soit `2^64`.

Comme les entiers non signés utilisent une arithmétique modulo 2^64 en cas de dépassement, les résultats intermédiaires deviennent incorrects pour les calculs attendus. Cela peut entraîner des erreurs lors du déchiffrement.

## Conclusion

Les tests montrent que la valeur de `MAX_PRIME` influence directement la fiabilité des opérations de chiffrement et de déchiffrement.

Pour les petites valeurs, les calculs restent suffisamment limités pour obtenir de bons résultats. Lorsque `MAX_PRIME` augmente, les dépassements de capacité deviennent plus fréquents et entraînent une augmentation importante du nombre d'échecs.


## 4. Exhaustivité des tests

Les tests permettent de vérifier les principales fonctionnalités demandées pour cette phase comme la génération et l'affichage des clés RSA, leur sauvegarde et leur chargement, ainsi que le chiffrement et le déchiffrement de caractères.

# Phase 1.1 

### Politique de tests

L'objectif est de vérifier que les fonctions `chiffrer_tab_octet` et `dechiffrer_tab_octet` permettent de chiffrer un tableau d'octets puis de retrouver exactement le message original après déchiffrement.

#### Tests réalisés

- **Test d'un message simple :** utilisation du message `"AAAA"` pour vérifier que le chiffrement et le déchiffrement fonctionnent sur un tableau contenant plusieurs fois le même caractère.
- **Vérification du résultat :** après le déchiffrement, comparaison du message obtenu avec le message original à l'aide de `memcmp`. Le test est réussi si les deux tableaux sont identiques.
- **Test sur plusieurs octets :** vérification que les fonctions traitent correctement plusieurs octets successifs dans un même tableau.
- **Test avec une paire de clés générée :** génération d'une paire de clés avant le chiffrement et le déchiffrement, afin de vérifier le fonctionnement avec les clés produites par le programme.


#### Critère de réussite

Le test est considéré comme réussi si le tableau obtenu après déchiffrement est identique au tableau d'octets initial. Dans le code actuel, cette vérification est réalisée avec `memcmp`.


# Phase 1.2 

### Politique de tests

L'objectif est de vérifier que les fonctions de chiffrement et de déchiffrement de fichiers permettent de retrouver le message original après les deux opérations successives.

#### Tests réalisés

- **Chiffrement et déchiffrement d'un fichier :** utilisation d'un fichier contenant un message, chiffrement de son contenu dans un autre fichier, puis déchiffrement dans un troisième fichier.
- **Vérification du contenu :** comparaison du fichier obtenu après déchiffrement avec le fichier original afin de vérifier que le message est identique.
- **Utilisation des clés :** vérification du fonctionnement des fonctions avec une paire de clés générée par le programme.
- **Gestion des fichiers :** vérification que les fonctions signalent une erreur lorsqu'un fichier ne peut pas être ouvert.

#### Critères de réussite

Un test est considéré comme réussi si :
- Le chiffrement du fichier se déroule correctement.
- Le déchiffrement du fichier chiffré se déroule correctement.
- Le fichier déchiffré contient exactement les mêmes octets que le fichier original.

#### Bilan

Cette politique de tests permet de vérifier le fonctionnement du chiffrement et du déchiffrement sur des fichiers, ainsi que la conservation du message original après déchiffrement.

# Phase 1.23

## Bilan des tests de validation

Les tests de validation ont pour objectif de vérifier le bon fonctionnement des fonctions d'encodage et de décodage Base64, en s'assurant que les données initiales sont correctement retrouvées après conversion.

Plusieurs types de données ont été utilisés pour tester les conversions : des entiers de types uint32_t et uint64_t, des chaînes de caractères, une clé RSA publique, une clé RSA privée et une paire de clés RSA.

Pour chaque test, les données sont encodées en Base64, puis décodées afin de comparer le résultat avec les données originales. La comparaison s'effectue sur les octets et les tailles des données.

Le test est validé si l'encodage en Base64 est correctement effectué et si le décodage permet de retrouver le message original.

### Compilation

À la racine du projet, exécuter la commande suivante :

Lancer la commande : make
puis executé l'executable pour lancer les tests: ./main 
