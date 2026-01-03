
---

### `writeup.md`

```markdown
# Write-up – Presque ça… (RSA mal implémenté avec module premier)

## 1. Énoncé

> « Presque ça... Je me suis endormi pendant la forma (formation).  
> De toute façon, RSA je connais ! Suffit de prendre un grand nombre premier et tout est sécurisé, non ? »

Lidée du challenge est de (dé)montrer qu’une compréhension incomplète de RSA conduit à une implémentation catastrophique :  
le modulus \(N\) est choisi **premier**, alors que RSA standard impose un produit de deux grands premiers \(N = p \cdot q\).

En disposant de :

- un script Python (`chall.py`) qui génère les paramètres,
- un fichier (`output.txt`) contenant une instance réelle :
  - \(N\) (1024 bits),
  - \(e = 65537\),
  - \(c\) le chiffrement du flag.

Le flag est au format :

```text
Star{F4ut_3c0ut3r_qu4nd_0n_p4rl3}

# Morale 
Non, « prendre un grand nombre premier » ne suffit pas à sécuriser RSA.
Au contraire, si 𝑁 est premier, 𝜑(𝑁) devient trivial (𝑁−1) et on peut retrouver la clé privée sans factorisation
