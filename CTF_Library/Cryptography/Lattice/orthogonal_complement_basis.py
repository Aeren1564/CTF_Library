# Source: https://github.com/maple3142/lll_cvp/blob/master/lll_cvp.py
# Find a short basis of orthogonal complements of the span of given vectors
def orthogonal_complement_basis(vecs, mod = None):
	from sage.all import ZZ, vector, matrix, block_matrix
	from CTF_Library.Cryptography.Lattice.reduce_lattice import reduce_lattice
	assert len(set(len(v) for v in vecs)) == 1
	vecs = list(vector(ZZ, map(int, v)) for v in vecs)
	nv = len(vecs)
	base = [[matrix(ZZ, vecs).T, matrix.identity(ZZ, len(vecs[0]))]]
	if mod != None:
		base += [[int(mod), 0]]
	L = block_matrix(ZZ, base)
	L[:, :nv] *= mod if mod != None else max([max(v) for v in vecs]) * 2**10
	L = reduce_lattice(L)
	return [vec for vec in L if vec[: nv] == 0]
