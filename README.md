# GhostRAM — Analyseur RAM Linux

Outil d'analyse de la mémoire physique Linux en temps réel via `/proc/kcore`,
construit avec [raylib](https://www.raylib.com/).

Focalisé sur la **détection de patterns**, la **heatmap d'activité** et la
**navigation visuelle** dans la RAM — pensé pour un usage perso / recherche (en vrai je trouvais ça "stylé" de faire une heatmap de ram).

---

## Compilation

```bash
# Ubuntu / Debian
sudo apt install libraylib-dev
gcc ghostram_v3.c -o ghostram -lraylib -lpthread -lm -ldl -lGL -O2

# Arch
sudo pacman -S raylib
gcc ghostram_v3.c -o ghostram -lraylib -lpthread -lm -ldl -lGL -O2

# Exécution (root obligatoire — /proc/kcore est protégé eh oui, pas le choix les loulous)
sudo ./ghostram
```

---

## Vues (F1 / F2 / F3)

| Touche | Vue       | Description |
|--------|-----------|-------------|
| F1     | HEX       | Vue hexadécimale avec coloration syntaxique et détection de patterns |
| F2     | HEATMAP   | Carte thermique d'activité sur toute la RAM physique (incroyable) |
| F3     | PATTERNS  | Liste détaillée de tous les patterns détectés dans la page courante |

---

## Raccourcis clavier

| Touche       | Action |
|--------------|--------|
| `Espace`     | Recherche (texte ou hex `AA BB CC`) |
| `G`          | Aller à une adresse (hex) |
| `B`          | Ajouter un bookmark à l'offset courant |
| `F`          | Cycler les filtres d'affichage |
| `A`          | Toggle auto-refresh (toutes les 300ms) |
| `L`          | Toggle live diff (coloration des octets modifiés) |
| `R`          | Refresh manuel de la page (je trouvais ça necessaire) |
| `TAB`        | Changer d'onglet dans la barre sur le coté |
| `↑ / ↓`      | Navigation ligne par ligne |
| Molette      | Scroll rapide dans la vue hex |
| `Échap`      | Annuler la saisie en cours |

---

## Fonctionnalités

### Recherche
- **Texte ASCII** : tape directement, ex : `passwd`
- **Hexadécimal** : octets séparés par des espaces, ex : `7F 45 4C 46`
- Détection automatique du mode (hex ou texte) (plutôt sympa ?)
- Thread dédié avec barre de progression et annulation propre (manière complexe de dire barre de chargement)

### Détection de patterns

Le moteur analyse chaque octet de la page et classe les données en 9 types :

| Couleur | Type        | Détection |
|---------|-------------|-----------|
|  Cyan   | STRING      | Run ASCII imprimable ≥ 5 caractères |
|  Bleu   | WSTRING     | Chaine UTF-16 LE (alternance ascii/`00`) ≥ 4 chars |
|  Violet | POINTER     | Pointeur 64bit (kernel `0xffff8...` ou user `0x4000..0x7fff...`) |
|  Orange | FLOAT32     | `float` plausible (exposant ≠ 0 et ≠ FF, aligné sur 4) |
|  Jaune  | FLOAT64     | `double` plausible (exposant ≠ 0 et ≠ 7FF, aligné sur 8) |
|  Rose   | X86PROLOG   | Prologue de fonction x86-64 (`push rbp; mov rbp,rsp` ou `sub rsp,N`) |
|  Vert   | HEAP_HDR    | Header glibc malloc (size field avec flag `prev_inuse`, aligné sur 8) |
|  Citron | ELF         | Magic ELF (Executable and Linkable Format) (`7F 45 4C 46`) |
|  Or     | PE          | Magic PE (Portable Executable) / MZ (`4D 5A`) au cas ou pour les vm |

D'ailleurs, petit annecdote mais le format PE commence par `4D 5A` ce qui représente M Z, les initiales de Mark Zbikowski, un dev de chez Microsoft dans les années 80.

Chaque byte survolé affiche un **tooltip** avec son adresse physique, sa valeur
décimale et hexadécimale, le type de pattern associé et sa valeur interprétée
(ex : `3.14159` pour un float, `-> 0xffff888001a3c000` pour un pointeur).

### Heatmap d'activité (j'adore ce coté graphique)

- Répartit `MAX_HEAT` cellules sur toute la RAM physique détectée
- Chaque cellule effectue **deux lectures espacées de 8ms** et mesure :
  - Le **delta** (octets qui ont changé entre les deux lectures)
  - La **densité** de non-zéros (occupation)
- Coloration sur 4 zones : bleu froid -> cyan -> vert/jaune -> rouge chaud
- **Clic sur une cellule** -> navigation directe vers cette zone en vue HEX
- Statistiques affichées : nombre de cellules inactives / faibles / moyennes / hot
- Calcul entièrement en thread background, n'impacte pas l'UI

### Filtres d'affichage

7 filtres activables avec `F` ou depuis l'onglet PATTERNS de la sidebar :

| Filtre   | Comportement |
|----------|-------------|
| TOUT     | Affiche tous les octets |
| ≠ ZERO   | Masque les octets nuls |
| ASCII    | N'affiche que les octets imprimables (0x20–0x7E) |
| PTRS     | Met en avant les blocs de 8 octets qui forment un pointeur canonique |
| FLOATS   | Met en avant les blocs de 4 octets qui forment un float plausible |
| X86      | Met en avant les zones contenant des prologues x86-64 |
| HEAP     | Met en avant les headers glibc malloc |

Les octets masqués s'affichent `··` en gris discret pour garder la lisibilité
de la grille.

### Bookmarks avec annotations

- Label personnalisé + note longue (160 caractères)
- Couleur auto par index
- Bouton `[N]` pour éditer la note, `[X]` pour supprimer
- Navigation 1-clic depuis la sidebar
- Visibles comme **lignes colorées** dans la minimap

### Minimap

- Vue de toute la RAM physique sur la colonne de droite
- Superpose : heatmap projetée + zones actives (vert) + bookmarks (couleur) (même si ça se voit pas beaucoup je vous assure que il y avait une idée jolie derriere tout ça)
- Rectangle doré = fenêtre courante
- **Clic ou drag** = navigation instantanée

### Sidebar (3 onglets)

- **ZONES** : zones de RAM non-nulles détectées en background, avec barre
  d'activité proportionnelle. Clic = navigation.
- **BOOKMARKS** : liste des bookmarks avec label, adresse et note.
- **PATTERNS** : résumé des hits par type sur la page courante + filtres rapides
  cliquables.

---

## Architecture technique

```
main()
  ├── kcore_parse_elf()        — parse les PT_LOAD du fichier ELF kcore
  ├── kcore_find_page_offset() — calcule PAGE_OFFSET
  ├── thr_zones()              — découverte des zones non-nulles 
  ├── thr_heat()               — mesure d'activité heatmap
  └── thr_search()             — recherche globale

phys_to_kcore(phys)    — convertit une adresse physique en offset fichier kcore
mem_read(buf, n, phys) — lecture via phys_to_kcore()
page_refresh()         — lecture page + live diff + detect_patterns()
detect_patterns()      — analyse les 640 octets courants, produit g_hits[]

draw_hex_view()        — rendu hex avec coloration patterns + tooltip survol
draw_heatmap_view()    — grille 2D heatmap cliquable
draw_patterns_view()   — liste détaillée des hits + histogramme par type
draw_sidebar()         — 3 onglets : zones / bookmarks / patterns+filtres
draw_minimap()         — vue RAM complète + nav clic
draw_header()          — barre de vues, champ input, infos offset
draw_footer()          — status bar + FPS
```

### Pourquoi `/proc/kcore` et pas `/dev/mem` ?

`/dev/mem` est limité (souvent restreint aux 1ers Mo) et nécessite
`CONFIG_STRICT_DEVMEM=n`. `/proc/kcore` expose la RAM complète sous forme
d'un fichier **ELF64** valide : les adresses physiques iomem ne correspondent
**pas** directement aux offsets du fichier — il faut parser les headers
`PT_LOAD` pour calculer la translation. GhostRAM le fait automatiquement
au démarrage (c'est pas trop beau quand même ?).

---

## Limitations

- **Root requis** — `/proc/kcore` n'est accessible qu'en root (prévisible)
- **Lecture seule** — écriture impossible via kcore (pas très derrangeant)
- **Pages non mappées** — certaines zones renvoient des lectures nulles
  (trous dans les PT_LOAD), c'est normal
- **x86-64 Linux uniquement** — le calcul de PAGE_OFFSET suppose une
  architecture 64bit avec le layout mémoire kernel standard

---

## Dépendances

| Lib       | Usage |
|-----------|-------|
| raylib ≥ 4.5 | rendu graphique, fenêtrage, input |
| pthread   | threads background (zones, heatmap, recherche) |
| libm      | `sqrtf`, `cosf`, `sinf` (heatmap spinner) |






Si vous avez des questions ou des suggestions de modifications, je suis disponible sur discord @fiakx, merci d'avoir tout lu.
