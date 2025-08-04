def extended_euclidean(*args):
	from sage.all import xgcd
	args = list(*args)
	if len(args) == 0:
		return 0, []
	def recurse(l, r):
		if r - l == 1:
			return abs(args[l]), [1 if args[l] > 0 else -1]
		m = l + r >> 1
		gl, cl = recurse(l, m)
		gr, cr = recurse(m, r)
		g, _cl, _cr = xgcd(gl, gr)
		return g, [_cl * x for x in cl] + [_cr * x for x in cr]
	return recurse(0, len(args))

if __name__ == "__main__":
	from math import gcd
	import random

	def test():
		g = random.randrange(1000)
		data = [g * random.randrange(500, 1000) for _ in range(10)]
		g, coef = extended_euclidean(data)
		assert len(coef) == len(data)
		assert g == gcd(*data) == sum(c * x for c, x in zip(coef, data))

	test()
