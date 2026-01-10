# GhostRAM
GhostRAM est un analyseur de mémoire vive (RAM) physique pour Linux, conçu pour l'exploration forensique et le débogage de bas niveau. En utilisant l'interface virtuelle /proc/kcore, cet outil permet de visualiser, de scanner et de cartographier les données résidant directement dans vos barrettes de RAM.

## Fonctionnalités Clés
Visualisation Hexadécimale Temps Réel : Un moteur de rendu fluide (via Raylib) affichant les offsets, les valeurs hexadécimales et la traduction ASCII correspondante.

Détection de Zones : Un algorithme d'analyse asynchrone qui parcourt la RAM pour identifier les blocs de données actifs séparés par des zones de "silence" (null bytes).

Recherche Globale Multi-threadée : Recherchez instantanément des chaînes de caractères (ASCII) à travers toute l'architecture System RAM. La recherche s'effectue en arrière-plan sans bloquer l'interface visuelle.

Architecture Thread-Safe : Utilisation intensive de pread() et de mutex pour permettre une lecture simultanée de la mémoire par l'affichage, la recherche et l'analyseur de zones.

# Comment ça marche ?
Le logiciel s'appuie sur deux piliers du système Linux :

`/proc/iomem` : Utilisé pour identifier précisément les plages d'adresses physiques réservées par le système à la "System RAM".

`/proc/kcore` : Un fichier virtuel représentant l'image de la mémoire dynamique du noyau au format ELF.

Contrairement à un simple éditeur hexadécimal, GhostRAM ne lit pas un fichier sur disque, mais accède directement au mapping de votre matériel.

# Installation & Compilation
Prérequis
Un système Linux (x86_64 de préférence).

La bibliothèque Raylib installée.

Les droits administrateur (Root) sont obligatoires pour lire /proc/kcore.

## Compilation
Utilisez la commande suivante pour compiler le projet :

```gcc main.c -o aethermem -lraylib -lpthread -lm -ldl -lrt -lX11```
## Exécution

```sudo ./aethermem```
## Avertissement de sécurité
Ce projet accède à des zones sensibles de la mémoire système. Bien qu'il soit en lecture seule (O_RDONLY), manipuler des fichiers noyau comme /proc/kcore peut exposer des données sensibles (mots de passe, clés de chiffrement en cours d'utilisation). Utilisez cet outil uniquement dans un cadre éducatif ou de débogage personnel.
