class linear_equation_solver_GF2:
	from CTF_Library.Cryptography.LinearAlgebra.linear_equation_solver_GF2_impl import linear_equation_solver_GF2_impl
	def __init__(self, n : int):
		assert 0 <= n
		self.n = n
		self.impl = self.linear_equation_solver_GF2_impl(n)
	def rank(self):
		return self.impl.rank();
	def nullity(self):
		return self.impl.nullity();
	# equation is represented as a bitmask
	def consistent(self, equation: int, output : int):
		if isinstance(equation, tuple):
			equation, output = equation[0], output ^ equation[1]
		assert isinstance(equation, int) and 0 <= equation < 2**self.n
		assert isinstance(output, int) and 0 <= output < 2
		equation, output = self.impl.reduce(equation, output)
		return equation != 0 or output == 0
	# equation is represented as a bitmask
	def add_equation_if_consistent(self, equation: int, output : int):
		if isinstance(equation, tuple):
			equation, output = equation[0], output ^ equation[1]
		assert isinstance(equation, int) and 0 <= equation < 2**self.n
		assert isinstance(output, int) and 0 <= output < 2
		return self.impl.add_equation_if_consistent(equation, output)
	# Returns (An assignment A, a basis B for solution set)
	# i.e. # of solutions is 2**len(B) and all solution can uniquely be represented as A + sum(S) where S is a subset of B
	def solve(self):
		return self.impl.solve();
	def all_solutions(self):
		assignment, basis = self.impl.solve()
		res = [assignment]
		for mask in range(1, 1 << len(basis)):
			for i in range(len(basis)):
				assignment ^= basis[i]
				if mask >> i & 1:
					break
			res.append(assignment)
		return res
