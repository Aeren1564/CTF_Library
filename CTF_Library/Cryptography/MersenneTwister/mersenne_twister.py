class mersenne_twister:
	from CTF_Library.Cryptography.BitVector.bit_vector import bit_vector
	def __init__(self, init_state, init_index, W, N, M, R, A, U, D, S, B, T, C, L, F):
		# init_state is a list of bit_vectors
		assert isinstance(init_state, list) and len(init_state) == N
		assert isinstance(init_index, int) and 0 <= init_index <= N
		assert 1 <= M < N
		assert 0 <= R < W
		self.state = init_state
		self.index = init_index
		self.W = W
		self.N = N
		self.M = M
		self.R = R
		self.A = A
		self.U = U
		self.D = D
		self.S = S
		self.B = B
		self.T = T
		self.C = C
		self.L = L
		self.F = F
		self._uint_call_count = 0
	@staticmethod
	def twist(mt, state):
		for i in range(mt.N):
			if isinstance(state[i], mt.bit_vector):
				y = state[(i + 1) % mt.N][:mt.R].concat(state[i][mt.R:])
				z = y.broadcast(0, mt.W) & mt.A
			else:
				y = state[i] & 2**mt.R | state[(i + 1) % mt.N] & 2**mt.R - 1
				z = mt.A if y & 1 else 0
			state[i] = state[(i + mt.M) % mt.N] ^ y >> 1 ^ z
	@staticmethod
	def temper(mt, x):
		x ^= x >> mt.U & mt.D
		x ^= x << mt.S & mt.D & mt.B
		x ^= x << mt.T & mt.D & mt.C
		x ^= x >> mt.L
		return x
	# https://github.com/python/cpython/blob/23362f8c301f72bbf261b56e1af93e8c52f5b6cf/Modules/_randommodule.c#L120
	def genrand_uint(self):
		self._uint_call_count += 1
		if self.index >= self.N:
			self.twist(self, self.state)
			self.index = 0
		x = self.state[self.index].copy()
		self.index += 1
		return self.temper(self, x)
	# https://github.com/python/cpython/blob/23362f8c301f72bbf261b56e1af93e8c52f5b6cf/Modules/_randommodule.c#L471
	def getrandbits(self, n):
		assert 0 <= n
		if n <= self.W:
			return self.genrand_uint()[self.W - n:]
		res = mersenne_twister.bit_vector()
		for i in range(0, n, self.W):
			res = res.concat(self.genrand_uint()[max(0, self.W - (n - i)):])
		return res
	# https://github.com/python/cpython/blob/main/Lib/random.py#L288
	def getrandbytes(self, n):
		return self.getrandbits(8 * n)
	# https://github.com/python/cpython/blob/ebf6d13567287d04683dab36f52cde7a3c9915e7/Modules/_randommodule.c#L187-L193
	# Returns equation for random() * 2**53, which will be an integer in range [0, 2**53)
	def random(self):
		a, b = self.genrand_uint(), self.genrand_uint()
		return b[6:].concat(a[5:])
	def uint_call_count(self):
		return self._uint_call_count

class mt19937(mersenne_twister):
	W = 32
	N = 624
	M = 397
	R = 31
	A = 0x9908B0DF
	U = 11
	D = 0xFFFFFFFF
	S = 7
	B = 0x9D2C5680
	T = 15
	C = 0xEFC60000
	L = 18
	F = 1812433253
	def __init__(self, init_state, init_index = 624):
		super().__init__(init_state, init_index, self.W, self.N, self.M, self.R, self.A, self.U, self.D, self.S, self.B, self.T, self.C, self.L, self.F)
	# https://github.com/python/cpython/blob/23362f8c301f72bbf261b56e1af93e8c52f5b6cf/Modules/_randommodule.c#L181
	@staticmethod
	def init_genrand(seed):
		assert 0 <= seed < 2**mt19937.W
		state = [seed] + [0] * (mt19937.N - 1)
		for i in range(1, mt19937.N):
			state[i] = mt19937.F * (state[i - 1] ^ state[i - 1] >> 30) + i & mt19937.D
		return state
	# https://github.com/python/cpython/blob/23362f8c301f72bbf261b56e1af93e8c52f5b6cf/Modules/_randommodule.c#L204
	@staticmethod
	def key_to_state(key):
		assert 0 < len(key) and (len(key) == 1 or key[-1] > 0)
		assert all(0 <= x < 2**mt19937.W for x in key)
		state = mt19937.init_genrand(19650218)
		i, j = 1, 0
		for _ in range(max(mt19937.N, len(key))):
			state[i] = (state[i] ^ (state[i - 1] ^ state[i - 1] >> 30) * 1664525) + key[j] + j & mt19937.D
			i, j = i + 1, (j + 1) % len(key)
			if i == mt19937.N:
				state[0] = state[mt19937.N - 1]
				i = 1
		for _ in range(mt19937.N - 1):
			state[i] = (state[i] ^ (state[i - 1] ^ state[i - 1] >> 30) * 1566083941) - i & mt19937.D
			i = i + 1
			if i == mt19937.N:
				state[0] = state[mt19937.N - 1]
				i = 1
		state[0] = 0x80000000
		state += [mt19937.N]
		return state

class mt19937_64(mersenne_twister):
	W = 64
	N = 312
	M = 156
	R = 31
	A = 0xB5026F5AA96619E9
	U = 29
	D = 0x5555555555555555
	S = 17
	B = 0x71D67FFFEDA60000
	T = 37
	C = 0xFFF7EEE000000000
	L = 43
	F = 6364136223846793005
	def __init__(self, init_state, init_index = 312):
		super().__init__(init_state, init_index, self.W, self.N, self.M, self.R, self.A, self.U, self.D, self.S, self.B, self.T, self.C, self.L, self.F)
