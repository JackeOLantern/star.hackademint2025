#!/usr/bin/env python3
import math
import re

def is_square(n: int):
    r = math.isqrt(n)
    return r*r == n, r

def fermat_factor(N: int):
    a = math.isqrt(N)
    if a*a < N:
        a += 1
    b2 = a*a - N
    ok, b = is_square(b2)
    if not ok:
        # au besoin itérer, mais ici ce n’est même pas nécessaire
        while True:
            a += 1
            b2 = a*a - N
            ok, b = is_square(b2)
            if ok:
                break
    p, q = a-b, a+b
    assert p*q == N
    return p, q

def grab(name: str, s: str) -> int:
    m = re.search(rf"\b{name}\s*=\s*([0-9]+)\b", s, re.IGNORECASE)
    if not m:
        raise ValueError(f"Champ {name} introuvable")
    return int(m.group(1))

data = open("params.txt", "r", encoding="utf-8").read()
N = grab("N", data)
e = grab("E", data)  # ou "e"
c = grab("C", data)  # ou "c"

p, q = fermat_factor(N)
phi = (p-1)*(q-1)
d = pow(e, -1, phi)
m = pow(c, d, N)

pt = m.to_bytes((m.bit_length()+7)//8, "big")
flag = pt.decode("utf-8")
assert pow(int.from_bytes(pt, "big"), e, N) == c  # validation

print(flag)
