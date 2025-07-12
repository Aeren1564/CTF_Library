# Let f be a monic non-constant polynomial over Z/mZ
# Return the list of integer r <= root_ub such that gcd(f(r), m) != 1
def coppersmith_univariate(m: int, f: list, root_ub: int):
	from sage.all import matrix, ZZ
	from math import gcd
	deg = len(f) - 1
	if f[-1] != 1:
		x = pow(f[-1], -1, m)
		for i in range(deg + 1):
			f[i] = f[i] * x % m
	assert m >= 2
	assert deg >= 1 and f[-1] == 1
	assert root_ub >= 1 and root_ub**deg < m
	lattice = []
	det, f_pow = 1, [1]
	while True:
		det *= m**len(lattice)
		for row in lattice:
			for i in range(len(row)):
				row[i] *= m
		for shift in range(deg):
			n = len(lattice)
			det *= root_ub**n
			lattice.append([0] * shift + f_pow)
			n += 1
			if n > deg and 2**(n - 1) * det**4 * (deg + 1)**(2 * n) < (m**((n - 1) // deg))**(4 * n):
				break
		else:
			f_pow_next = [0] * (len(lattice) + 1)
			for i, x in enumerate(f):
				for j, y in enumerate(f_pow):
					f_pow_next[i + j] += x * y
			f_pow = f_pow_next
			continue
		break
	n = len(lattice)
	print(f"[INFO] <coppersmith_univariate> lattice dimension {n}")
	for i in range(n):
		root_ub_pow = 1
		lattice[i] += [0] * (n - 1 - i)
		for j in range(n):
			lattice[i][j] *= root_ub_pow
			root_ub_pow *= root_ub
	roots = []
	lattice = [list(map(int, row)) for row in matrix(lattice).LLL()]
	for i in range(n):
		root_ub_pow = 1
		for j in range(n):
			assert lattice[i][j] % root_ub_pow == 0
			lattice[i][j] //= root_ub_pow
			root_ub_pow *= root_ub
	for row in lattice:
		for root, _ in ZZ['X'](row).roots():
			if 0 <= root <= root_ub:
				x = 0
				for c in reversed(f):
					x = (root * x + c) % m
				if gcd(m, x) != 1:
					roots.append(root)
	return list(sorted(set(roots)));

if __name__ == "__main__":
	from math import gcd
	def eval_at(m, f, x):
		y = 0
		for c in reversed(f):
			y = (x * y + c) % m
		return y
	def test_coppersmith_univariate(m, f, root_ub):
		expected = []
		for x in range(root_ub + 1):
			if gcd(m, eval_at(m, f, x)) != 1:
				expected.append(x)
		print(f"[test_coppersmith_univariate] {expected = }")
		assert coppersmith_univariate(m, f, root_ub) == expected
	test_coppersmith_univariate(10001, [-222, 5000, 10, 1], 5)
	test_coppersmith_univariate((2**30 + 3) * (2**32 + 15), [1942528644709637042, 1234567890123456789, 987654321987654321, 1], 2**14)