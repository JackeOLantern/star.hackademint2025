#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Solveur "Intro" — RSA avec facteurs proches (q = next_prime(p)) via factorisation de Fermat.
#
# Demande utilisateur:
# - Commenter (quasi) chaque ligne pour expliciter le déroulement.
# - Ajouter un mode -v/--verbose qui affiche les étapes intermédiaires SUR STDOUT.

from __future__ import annotations  # Permet les annotations de type forward sans guillemets.

import argparse  # Gestion des arguments de ligne de commande (ex: -v, --params, --max-iters).
import math      # Fournit isqrt() pour la racine carrée entière, clé pour Fermat.
import re        # Extraction de N, e, c depuis un fichier texte via regex.
import sys       # Accès à sys.exit / codes de retour.

# ----------------------------- Affichage / Helpers -----------------------------

def vprint(verbose: bool, msg: str) -> None:
    """Imprime msg sur STDOUT uniquement si verbose=True."""
    if verbose:                         # Si l'utilisateur a demandé le mode verbeux...
        print(msg, flush=True)          # ... on imprime immédiatement (flush pour affichage "live").


def short_hex(x: int, head: int = 12, tail: int = 12) -> str:
    """
    Raccourci lisible d'un grand entier:
    - Affiche en hexadécimal avec le début et la fin, ex: 0x1234..cdef (bits=2048)
    """
    hx = hex(x)                         # Représentation hexadécimale Python (ex: '0xabc...').
    if len(hx) <= 2 + head + tail:      # Si c'est déjà court, on l'affiche en entier.
        return f"{hx} (bits={x.bit_length()})"
    return f"{hx[:2+head]}..{hx[-tail:]} (bits={x.bit_length()})"  # Tronquage tête/queue + bits.


# ----------------------------- Math utilitaires --------------------------------

def is_square(n: int) -> tuple[bool, int]:
    """
    Test de carré parfait:
    - Retourne (True, r) si r^2 == n
    - Sinon (False, floor(sqrt(n)))
    """
    if n < 0:                           # Un carré parfait ne peut pas être négatif.
        return (False, 0)               # On renvoie faux + racine 0.
    r = math.isqrt(n)                   # Racine carrée entière: r = floor(sqrt(n)).
    return (r * r == n, r)              # Vérifie si r^2 retombe exactement sur n.


def fermat_factor(N: int, *, verbose: bool = False, max_iters: int = 5_000_000, log_every: int = 100_000) -> tuple[int, int, int, int, int]:
    """
    Factorisation de Fermat (rapide quand p et q sont proches):
      N = p*q = (a-b)(a+b) avec:
        a = ceil(sqrt(N))
        b^2 = a^2 - N  (doit être un carré parfait)

    Retour:
      (p, q, iters, a_found, b_found)
    """
    a = math.isqrt(N)                   # a0 = floor(sqrt(N)).
    if a * a < N:                       # Si a0^2 < N...
        a += 1                          # ... alors a0 = ceil(sqrt(N)).
    vprint(verbose, f"[fermat] a0 = ceil(sqrt(N)) = {a}")
    vprint(verbose, f"[fermat] N = {short_hex(N)}")

    for i in range(max_iters):          # Itère sur a = a0, a0+1, a0+2, ...
        b2 = a * a - N                  # Calcule b^2 candidat.
        ok, b = is_square(b2)           # Teste si b2 est un carré parfait (b^2).
        if i == 0:                      # Premier essai: souvent suffisant quand p~q.
            vprint(verbose, f"[fermat] i=0: b2 = a0^2 - N = {short_hex(b2)}")
            vprint(verbose, f"[fermat] i=0: is_square(b2) = {ok}")

        if ok:                          # Si b2 est un carré parfait...
            p = a - b                   # ... alors p = a - b.
            q = a + b                   # ... et q = a + b.
            if p * q == N:              # Vérification forte: on doit retrouver exactement N.
                vprint(verbose, f"[fermat] FOUND at i={i}")
                vprint(verbose, f"[fermat] a = {a}")
                vprint(verbose, f"[fermat] b = {b}")
                vprint(verbose, f"[fermat] p = {short_hex(p)}")
                vprint(verbose, f"[fermat] q = {short_hex(q)}")
                vprint(verbose, f"[fermat] q-p = {q - p}")
                return (p, q, i, a, b)  # Retourne facteurs + itération + (a,b) trouvés.

        if verbose and (i != 0) and (i % log_every == 0):  # Logs périodiques si recherche longue.
            vprint(verbose, f"[fermat] progress: i={i}, current a={a}")

        a += 1                          # Essai suivant.

    raise RuntimeError("Fermat factorisation failed: increase --max-iters or verify that p and q are close.")


# ----------------------------- Parsing des paramètres --------------------------

def grab(name: str, s: str) -> int:
    """Extrait un entier depuis une ligne 'name = <decimal>' (insensible à la casse)."""
    m = re.search(rf"\b{name}\s*=\s*([0-9]+)\b", s, re.IGNORECASE)  # Cherche 'name = <digits>'.
    if not m:                           # Si non trouvé...
        raise ValueError(f"Champ {name} introuvable (attendu: '{name} = <int>').")  # Erreur claire.
    return int(m.group(1))              # Convertit la valeur capturée en int.


# ----------------------------- Programme principal -----------------------------

def main() -> int:
    """Point d'entrée du solveur: lit N/e/c, factorise N, déchiffre, valide, affiche le flag."""
    ap = argparse.ArgumentParser(description="Solveur Intro (RSA p~q) via Fermat + déchiffrement RSA.")
    ap.add_argument("--params", default="params.txt", help="Fichier contenant N=..., e=..., c=... (défaut: params.txt).")
    ap.add_argument("--max-iters", type=int, default=5_000_000, help="Max itérations Fermat (défaut: 5e6).")
    ap.add_argument("--log-every", type=int, default=100_000, help="En verbose, log toutes les N itérations (défaut: 100000).")
    ap.add_argument("-v", "--verbose", action="store_true", help="Affiche les étapes intermédiaires sur stdout.")
    args = ap.parse_args()

    verbose = bool(args.verbose)        # Convertit en bool propre.

    # Lecture du fichier de paramètres (N, e, c).
    vprint(verbose, f"[+] reading params from: {args.params}")
    try:
        data = open(args.params, "r", encoding="utf-8", errors="replace").read()  # Charge tout le fichier.
    except OSError as e:
        print(f"[!] cannot read {args.params}: {e}", flush=True)                  # Erreur sur stdout (cohérent avec demande).
        return 2

    # Extraction des paramètres RSA.
    N = grab("N", data)                 # Modulus N.
    e = grab("e", data)                 # Exposant public e (souvent 65537).
    c = grab("c", data)                 # Ciphertext c.
    vprint(verbose, f"[+] N bits = {N.bit_length()}")
    vprint(verbose, f"[+] e = {e}")
    vprint(verbose, f"[+] c bits = {c.bit_length()}")

    # 1) Factorisation de N.
    vprint(verbose, "[1/5] factoring N with Fermat (expects p and q close)")
    p, q, iters, a_found, b_found = fermat_factor(N, verbose=verbose, max_iters=args.max_iters, log_every=args.log_every)

    # Normalisation (optionnelle): p < q pour lecture plus intuitive.
    if p > q:
        p, q = q, p

    # 2) Calcul de phi(N) = (p-1)(q-1).
    vprint(verbose, "[2/5] computing phi(N) = (p-1)(q-1)")
    phi = (p - 1) * (q - 1)
    vprint(verbose, f"[+] phi bits = {phi.bit_length()}")

    # 3) Calcul de la clé privée d = e^{-1} mod phi.
    vprint(verbose, "[3/5] computing d = inverse(e) mod phi(N)")
    try:
        d = pow(e, -1, phi)             # Python 3.8+: inversion modulaire via pow.
    except ValueError as ex:
        print(f"[!] cannot invert e modulo phi(N): {ex}", flush=True)
        return 3
    vprint(verbose, f"[+] d bits = {d.bit_length()}")

    # 4) Déchiffrement: m = c^d mod N.
    vprint(verbose, "[4/5] decrypting m = c^d mod N")
    m = pow(c, d, N)
    vprint(verbose, f"[+] m = {short_hex(m)}")

    # Conversion en bytes.
    pt_len = (m.bit_length() + 7) // 8  # Longueur minimale en octets.
    pt = m.to_bytes(pt_len, "big")      # Big-endian comme RSA classique.
    vprint(verbose, f"[+] plaintext length (bytes) = {len(pt)}")
    vprint(verbose, f"[+] plaintext (hex) head/tail = {pt[:16].hex()}..{pt[-16:].hex() if len(pt) >= 16 else pt.hex()}")

    # Tentative de décodage du flag.
    try:
        flag = pt.decode("utf-8")        # Le flag est attendu UTF-8 / ASCII.
    except UnicodeDecodeError:
        flag = pt.decode("latin-1")      # Fallback: latin-1 (permet d'afficher n'importe quel octet).

    vprint(verbose, f"[+] decoded flag candidate = {flag!r}")

    # 5) Validation: rechiffre le message et compare au ciphertext.
    vprint(verbose, "[5/5] validating: pow(m,e,N) == c")
    m_back = int.from_bytes(pt, "big")   # Reconstruit l'entier depuis les bytes.
    c_check = pow(m_back, e, N)          # Rechiffrement RSA.
    if c_check != c:
        print("[!] validation FAILED: re-encryption does not match ciphertext", flush=True)
        vprint(verbose, f"[dbg] c_check = {short_hex(c_check)}")
        vprint(verbose, f"[dbg] c       = {short_hex(c)}")
        return 4

    vprint(verbose, "[+] validation OK")

    # Sortie finale:
    # - En mode non-verbeux: un seul print(flag)
    # - En mode verbeux: les logs sont déjà sur stdout, et le flag est la DERNIÈRE ligne.
    print(flag, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())             # Exécute main() et propage le code de retour.
