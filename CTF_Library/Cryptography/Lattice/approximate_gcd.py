# Source: https://eprint.iacr.org/2024/1125.pdf
# simultaneous diophantine approximation approach for general approximate gcd problem
#
# Let p be a random eta-bit positive integer such that
# a[i] = p * q[i] + r[i], q[i] > 0, and -2**rho < r[i] < 2**rho for all 0 <= i < len(a)
# Returns one possible value of q[0]
# Note that when all q[i] shares a common factor, it may arbitrarily be included in p
def approximate_gcd_sda(a: list, eta: int, rho: int):
	from sage.all import matrix, zero_matrix, block_matrix
	from CTF_Library.Cryptography.Lattice.reduce_lattice import reduce_lattice
	n, a = len(a), list(map(int, a))
	assert n >= 2 and min(a) > 0
	gamma = max(x.bit_length() for x in a)
	assert gamma > eta > rho > 0 and n * (eta - rho) > (gamma - rho)
	for vec in reduce_lattice(block_matrix([[2**(rho + 1), matrix(a[1 : ])], [zero_matrix(n - 1, 1), -a[0]]])):
		if vec[0] != 0:
			return int(abs(vec[0])) >> rho + 1
	assert False

# (WARNING) SEEMS WRONG?
# Source: https://eprint.iacr.org/2024/1125.pdf
# simultaneous diophantine approximation approach for partial approximate gcd problem
# Returns a random eta-bit positive integer p such that
# a[i] = p * q[i] + r[i], q[i] > 0, and -2**rho < r[i] < 2**rho for all 0 <= i < len(a)
# Note that when all q[i] shares a common factor, it may arbitrarily be included in p
# multiple_of_p must be a multiple of p
def partial_approximate_gcd_sda(multiple_of_p: int, a: list, eta: int, rho: int):
	from sage.all import matrix, zero_matrix, block_matrix
	from CTF_Library.Cryptography.Lattice.reduce_lattice import reduce_lattice
	n, a = len(a), list(map(int, a))
	assert n >= 2 and min(a) > 0
	gamma = max(x.bit_length() for x in a)
	assert gamma > eta > rho > 0 and n * (eta - rho) > (gamma - rho)
	for vec in reduce_lattice(block_matrix([[2**(rho + 1), matrix(a)], [zero_matrix(n, 1), -multiple_of_p]])):
		if vec[0] != 0:
			return int(abs(vec[0])) >> rho + 1
	assert False

# Source: https://eprint.iacr.org/2018/1208.pdf
# orthogonal lattice approach for general approximate gcd problem
#
# Recover a list of random positive integers q such that
# 1. a[i] = p * q[i] + r[i],
# 2. p is a random eta-bit positive integer, and
# 3. -2**rho < r[i] < 2**rho for all 0 <= i < len(a)
# Note that floor(a[i] / q[i]) = p + floor(r[i] / q[i])
# If gamma > eta + rho, p = floor(a[i] / q[i])
# If gamma <= eta + rho, floor(a[i] / q[i]) gives the most gamma - rho - 1 significant bits of p
def approximate_quotients_orthogonal_lattice(a: list, eta: int, rho: int):
	from gmpy2 import get_context, ceil, sqrt, log2
	get_context().precision = 1000
	from sage.all import matrix, block_matrix
	from CTF_Library.Cryptography.Lattice.reduce_lattice import reduce_lattice
	n, a = len(a), list(map(int, a))
	assert n >= 2 and min(a) > 0
	gamma = max(x.bit_length() for x in a)
	assert gamma > eta > rho > 0
	alpha = int(ceil(sqrt(n) * 2**rho / (n - 1) / (sqrt(n) + 1)))
	mat = reduce_lattice(block_matrix([[matrix([x // alpha for x in a]).T, 1]]))
	det = 1
	for vec in mat:
		det *= sqrt(sum(int(x)**2 for x in vec))
	delta_0 = pow(sqrt(sum(int(x)**2 for x in mat[-1])) / pow(det, 1.0 / n), 1.0 / n)
	# geometric series assumption 
	assert (gamma - rho) / n - (eta - rho) + n * log2(delta_0) + log2(sqrt(n * (n + 2))) < 0
	q = [int(abs(basis[-1])) for basis in mat[:, 1:].inverse()]
	assert min(q) > 0
	return q

# Source: https://eprint.iacr.org/2018/1208.pdf
# orthogonal lattice approach for general approximate gcd problem
#
# Recover a random eta-bit positive integer p such that
# a[i] = p * q[i] + r[i], q[i] > 0, and -2**rho < r[i] < 2**rho for all 0 <= i < len(a)
# Note that when all q[i] shares a common factor, it may arbitrarily be included in p
def approximate_gcd_orthogonal_lattice(a: list, eta: int, rho: int):
	assert len(a) >= 2 and min(a) > 0
	gamma = max(x.bit_length() for x in a)
	assert gamma > eta + rho
	q = approximate_quotients_orthogonal_lattice(a, eta, rho)
	assert all(a[i] // q[i] == a[0] // q[0] for i in range(1, len(a)))
	return int(a[0] // q[0])

"""
Tested on
- AlpacaHack2024 Round 5/nnnn
- WMCTF2024/crypto/FACRT
"""