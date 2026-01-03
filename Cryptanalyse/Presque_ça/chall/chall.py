from Crypto.Util.number import getStrongPrime, bytes_to_long

N = getStrongPrime(1024)
e = 65537

FLAG = "Star{Fake_flag}"

c = pow(bytes_to_long(FLAG.encode()), e, N)

print(f'N = {N}')
print(f'e = {e}')
print(f'c = {c}')