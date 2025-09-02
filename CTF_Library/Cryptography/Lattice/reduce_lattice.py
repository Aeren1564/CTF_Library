# mat must be a sagemath matrix
def reduce_lattice(mat):
	from re import findall
	from subprocess import check_output
	from sage.all import matrix
	print(f"[INFO]<reduce_lattice> matrix of size {mat.nrows()}x{mat.ncols()}")
	mat_str = "[[" + "]\n[".join(" ".join(map(str, row)) for row in mat) + "]]"
	res = list(map(int, findall(b"-?\\d+", check_output(["flatter"], input = mat_str.encode()))))
	assert len(res) % mat.ncols() == 0
	print(f"[INFO]<reduce_lattice> finished")
	return matrix(len(res) // mat.ncols(), mat.ncols(), res)
