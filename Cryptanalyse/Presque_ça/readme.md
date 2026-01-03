# Presque ça… (RSA avec module premier)

> « Presque ça... Je me suis endormi pendant la forma(tion).  
> De toute façon, RSA je connais ! Suffit de prendre un grand nombre premier et tout est sécurisé, non ? »

## 1. Description

Ce challenge illustre une mauvaise implémentation de RSA :  
le modulus \(N\) n’est pas un produit de deux grands nombres premiers, mais **un seul nombre premier**.  

Cela rend la fonction d’Euler \(\varphi(N)\) triviale à calculer :
\[
\varphi(N) = N - 1 \quad \text{si } N \text{ est premier}.
\]

On peut donc récupérer la clé privée et déchiffrer le flag.

---

## 2. Fichiers fournis

- `chall.py`  
  Génère un grand premier `N`, fixe `e = 65537`, et chiffre une chaîne `"Star{...}"` :

  ```python
  from Crypto.Util.number import getStrongPrime, bytes_to_long

  N = getStrongPrime(1024)
  e = 65537

  FLAG = "Star{Fake_flag}"

  c = pow(bytes_to_long(FLAG.encode()), e, N)
