"""
The system of modular equations X = r_i modulo mod_i has following unique solution, assuming it has at least one solution
X = sum(coef_i * r_i) modulo lcm(mod_i)
"""
def CRT_coefficients(mods):
	from sage.all import xgcd
	if len(mods) == 0:
		return []
	assert min(mods) >= 1
	def recurse(l, r):
		if r - l == 1:
			return [1], int(mods[l])
		m = l + r >> 1
		lcoef, lmod = recurse(l, m)
		rcoef, rmod = recurse(m, r)
		g, cl, cr = xgcd(lmod, rmod)
		mod = lmod // g * rmod
		if cl < 0:
			cl += mod
		if cr < 0:
			cr += mod
		return [rmod // g * cr * x % mod for x in lcoef] + [lmod // g * cl * x % mod for x in rcoef], mod
	return recurse(0, len(mods))[0]

if __name__ == "__main__":
	import random
	from math import prod, lcm

	obj = random.getrandbits(9000)
	mods = [random.getrandbits(1000) for _ in range(10)]

	mod = lcm(*mods)
	obj %= mod
	rems = [obj % mod for mod in mods]
	coef = CRT_coefficients(mods)
	s = 0
	for c, r in zip(coef, rems):
		s += c * r
	assert s % mod == obj
