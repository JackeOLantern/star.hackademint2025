from sage.all import next_probable_prime, random_prime, gcd
from binascii import hexlify
import os

e = 65537
# 1024-bit prime p with gcd(e, p-1)=1
p = random_prime(2**1024-1, lbound=2**1023)
while gcd(e, p-1) != 1:
    p = random_prime(2**1024-1, lbound=2**1023)

q = next_probable_prime(p)  # q = next prime after p (primes "proches")
N = p*q

FLAG = os.getenv("FLAG") or "Star{fake_flag_for_testing_purposes}"
m = int.from_bytes(FLAG.encode(), "big")
c = pow(m, e, N)

print(f"N = {N}")
print(f"e = {e}")
print(f"c = {c}")
