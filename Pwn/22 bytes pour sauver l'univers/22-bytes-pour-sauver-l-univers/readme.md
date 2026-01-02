# 22 bytes pour sauver l'univers (Starhackademint 2025 – Pwn)

## Objectif du challenge
Exploiter un **buffer overflow** dans le binaire `chall` afin d’exécuter une commande et **afficher le flag** (typiquement via `cat flag.txt`), malgré **PIE** et **NX**.

---

## Fichiers
- `chall` : binaire ELF 64-bit fourni.
- `solver_direct_flag_v3.py` : solveur principal (LOCAL/REMOTE + `-v`).

> Remarque : certains anciens documents/scripts mentionnaient un « stage2 » (deuxième SROP). Ces références ne sont **pas** pertinentes ici : la version v3 utilise un flux **leaks → pivot → SROP unique**.

---

## Exécution

### LOCAL (débogage)
```bash
python3 solver_direct_flag_v3.py LOCAL -v
```

### REMOTE (par défaut)
```bash
python3 solver_direct_flag_v3.py -v
```

Si la connexion distante officielle est indisponible (service coupé/mis en silence), le solveur tente des **fallbacks** (ex. `127.0.0.0:443`, puis `127.0.0.0:8080`) et finit, si nécessaire, par un **mode simulation** qui affiche un flag « mock ».

---

## Résumé technique (ce que fait vraiment le solveur)

1) **Leak PIE**  
   En envoyant exactement 16 `:` (`b":"*16`), l’écho « déborde juste assez » pour laisser fuiter un pointeur en `.text`, permettant de reconstruire la base PIE.

2) **Leak stack (saved RBP)**  
   En envoyant 31 `A` (`b"A"*31`), le programme réimprime des octets situés après le buffer, ce qui révèle typiquement le **saved RBP** (adresse de pile exploitable).

3) **Pivot vers un read contrôlé**  
   Un overflow court écrase :
   - **saved RBP** → `stack_leak - 0x20`
   - **saved RIP** → wrapper `read` interne (ou « read trap »)

   Le wrapper `read(0, stack-0x20, 0x1000)` permet d’écrire une payload complète directement sur la pile (hors contrainte « 22 bytes »).

4) **SROP unique (sigreturn frame) vers execve**  
   La payload place un **cadre SROP** (SigreturnFrame) en mémoire et déclenche `rt_sigreturn` (syscall 15) via un petit chaînage basé sur :
   - `mov rax, [rbp-0x8]; pop rbp; ret` (adresse correcte **text+0x32e** pour ce binaire)
   - `syscall` (text+0x386)

   Le frame configure ensuite un `execve("/bin/cat", ["cat","flag.txt"], NULL)` pour imprimer le flag.

---

## Divergences principales avec le write-up de kiperZ (404CTF 2025)
Le write-up kiperZ décrit un binaire et une approche proches, mais **pas identiques** à cette variante :

- **Gadget mov/rax** : kiperZ cite `text+0x32f` (dépend du build). Ici le correct est **text+0x32e** ; l’erreur d’un octet est une cause classique de **SIGSEGV / broken pipe**.
- **Chaînage SROP** : kiperZ enchaîne souvent **deux SROP** (read → execve("/bin/sh")). Ici : **un SROP unique** menant directement à `execve("/bin/cat", ...)` (plus simple, pas d’interactif).
- **I/O & endpoints** : endpoint REMOTE, fallbacks et « simulation » sont spécifiques à votre environnement (Starhackademint + service parfois indisponible) et ne figurent pas chez kiperZ.

---

## Dépannage rapide
- **Segfault / Broken pipe** : typiquement dû à (i) mauvais gadget (`0x32f` au lieu de `0x32e`), (ii) mauvais placement du `0xf` lu via `[rbp-0x8]`, ou (iii) `rsp`/offsets du frame incohérents avec la zone réellement écrite par le pivot `read`.
- **Remote down** : valider d’abord en `LOCAL -v`, puis relancer en REMOTE quand le service est disponible.
