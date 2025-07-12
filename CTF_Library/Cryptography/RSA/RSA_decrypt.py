def RSA_decrypt(primes: list, e : int, enc : int):
	from Crypto.Util.number import inverse, isPrime
	from math import prod
	from sage.all import pari, Zmod
	assert all(isPrime(p) for p in primes)
	assert e > 0
	mod = prod(primes)
	assert 0 <= enc < mod
	for p in primes:
		pari.addprimes(p)
	return list(map(int, Zmod(mod)(enc).nth_root(e, all = True)))
