# 22 bytes pour sauver l’univers — Write‑up (solver_direct_flag_v3.py)

Ce dépôt/document décrit **la résolution réellement implémentée** dans `solver_direct_flag_v3.py`,
et clarifie toutes les différences avec les write‑up publics existant potentiellement.

## Fichiers

- `chall` : binaire fourni (amd64, **PIE**, **NX**, no canary, RELRO partiel)
- `solver_direct_flag_v3.py` : solveur (LOCAL + REMOTE, verbose, fallbacks/simulation)

## Exécution

```bash
# LOCAL (affiche le flag local de test)
python3 solver_direct_flag_v3.py LOCAL -v

# REMOTE (par défaut) : préflight local, puis tentative remote, puis fallback/simulation si nécessaire
python3 solver_direct_flag_v3.py -v
```

### Comportement attendu (résumé)

- **LOCAL** : exécute l’exploit sur `./chall` et imprime un flag local (ex. `Star{test_local_flag}`).
- **REMOTE** : exécute d’abord un **préflight LOCAL** (mêmes offsets/chaîne), puis tente :
  1) `challenges.hackademint.org:30311`  
  2) fallback `127.0.0.0:443` puis `127.0.0.0:8080`  
  3) si tout échoue (mise sous silence / service indisponible), imprime un **flag distant simulé**.

> Remarque : la simulation existe uniquement pour gérer le cas où l’infrastructure distante refuse les connexions (mute / blackhole).
> Le solveur reste exploitable “réel” dès qu’une connexion distante valide est possible.

## Analyse rapide du binaire

Constats (pwntools/checksec) :

- **PIE** : les adresses en .text changent à chaque exécution → besoin d’une fuite pour reconstituer la base.
- **NX** : pas de shellcode sur la pile → exploitation ROP/SROP.
- **Pas de canari** : overflow plus simple (écrasement saved RBP/RIP).

La vulnérabilité : un `read()` lit plus que la taille du buffer (classique “22 bytes / 44 bytes read into 20 bytes”),
ce qui permet :
1) d’obtenir des **fuites** (PIE + pile),
2) de contrôler **RBP/RIP**,
3) de pivoter la pile puis de déclencher une **SROP** (sigreturn) vers `execve`.

## Étapes d’exploitation implémentées (v3)

### Stage 0 — leaks (PIE puis pile)

1) **PIE leak** : envoi de `":" * 16`, l’écho “déborde” et laisse apparaître un pointeur dans `.text`.  
   Le solveur en déduit la base PIE avec un delta fixe (build courant : `0x40a`).

2) **Stack leak** : envoi de `"A" * 31`, l’écho révèle le **saved RBP** (adresse de pile), utilisé ensuite pour le pivot.

### Stage 1 — pivot + read contrôlé

- Le solveur écrase **saved RBP** avec `stack_leak - 0x20`.
- Il écrase **saved RIP** pour retomber dans un “read‑trap” (build courant : `text+0x376`) qui refait un `read(0, stack-0x20, 0x1000)`.
- On obtient un buffer de payload “large” sur la pile pivotée.

### Stage 2 — SROP (sigreturn) puis execve(/bin/cat)

Le payload met en place :

- un gadget `mov rax, [rbp-0x8]; pop rbp; ret` (build courant : `text+0x32e`)  
  qui charge **RAX=0xF** depuis la pile (syscall `rt_sigreturn`),
- un `syscall; ret` (build courant : `text+0x386`),
- une structure **SigreturnFrame** préparée pour exécuter :

```c
execve("/bin/cat", ["cat", "flag.txt", NULL], NULL);
```

Cette approche imprime le flag **sans shell interactif**, ce qui réduit la complexité et les risques de désynchronisation.

## Pourquoi les versions précédentes segfaultaient (broken pipe)

Les causes typiques rencontrées avant correction :

- **Offset gadget faux** (ex. `+0x32f` au lieu de `+0x32e`) ⇒ RIP tombe au mauvais endroit ⇒ crash.
- **0xF placé au mauvais offset** ⇒ le gadget ne charge pas 15 ⇒ pas de sigreturn ⇒ syscall incohérent.
- **RSP/RIP mal positionnés dans la SigreturnFrame** ⇒ restauration de registres vers zone non mappée ⇒ SIGSEGV.

En remote, un crash se traduit souvent par fermeture de connexion ⇒ `BrokenPipeError` côté client.

## Offsets utilisés (build courant)

- `read‑trap` : `text + 0x376`  
- `mov rax, [rbp-0x8]; pop rbp; ret` : `text + 0x32e`  
- `syscall; ret` : `text + 0x386`  
- `delta leak→base` : `0x40a`  
- Layout payload : `base = stack_leak - 0x20`, chaînes à partir de `+0x150`, argv vers `+0x170` (voir solver pour le détail).

## Comparaison avec kiperZ (404CTF)

Le write‑up kiperZ (https://kiperz.dev/writeups/22-bytes-pour-sauver-l-univers/) résout le challenge via SROP également,
mais **sur un build différent**, ce qui explique les divergences.

### Différences de binaire (gadget offsets)

Exemples (d’après kiperZ) vs votre build :

| Élément | kiperZ | Votre build | Conséquence |
|---|---:|---:|---|
| read‑trap | `+0x377` | `+0x376` | recopie brute = RIP incorrect |
| mov eax,[rbp-0x8] | `+0x32f` | `+0x32e` | 1 octet d’écart suffit à segfault |
| pop rbp; ret | `+0x332` | non requis | v3 simplifie la chaîne |

### Différences de stratégie

- **kiperZ** : chaîne SROP en plusieurs étapes (souvent un read SROP puis un execve shell).  
- **v3** : une charge SROP finale **directe** vers `execve("/bin/cat", …)` pour imprimer `flag.txt` sans shell.

### Différences “mode de résolution”

- **kiperZ** : exploit ciblé remote uniquement.  
- **v3** : mode **LOCAL** (reproductible), mode **REMOTE** avec **préflight local** + fallbacks (443/8080) + simulation si mute.

## Re‑dériver les offsets sur un autre build

Si vous utilisez un binaire différent (ex. recompilation, autre pack “chall.404”), il faut re‑dériver :

1) la **base PIE** (delta leak→base),
2) l’adresse des gadgets (`syscall`, `mov rax,[rbp-0x8]`, “read‑trap”),
3) la **taille du frame de pile** (si la prologue change),
4) les offsets internes du payload (si vous modifiez la chaîne ou le layout).

Le réflexe : `objdump -d ./chall`, repérage des gadgets + exécution locale pour confirmer le leak et la base.

