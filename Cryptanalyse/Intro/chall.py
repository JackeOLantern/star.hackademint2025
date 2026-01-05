from sage.all import next_probable_prime as next_brother
from Crypto.Util.number import getStrongPrime, bytes_to_long
import os

Joe = getStrongPrime(1024)
Jack = next_brother(Joe)
N = Joe*Jack
e = 0x10001

FLAG = os.getenv("FLAG") or "Star{fake_flag_for_testing_purposes}"

c = pow(bytes_to_long(FLAG.encode()), e, N)

print(f'N = {N}')
print(f'e = {e}')
print(f'c = {c}')
