class python_random_breaker:
	from CTF_Library.Cryptography.MersenneTwister.mersenne_twister import mt19937 as mt
	from CTF_Library.Cryptography.BitVector.bit_vector import make_bit_vector
	from CTF_Library.Cryptography.LinearAlgebra.linear_equation_solver_GF2 import linear_equation_solver_GF2
	W = mt.W
	N = mt.N
	M = mt.M
	R = mt.R
	A = mt.A
	U = mt.U
	D = mt.D
	S = mt.S
	B = mt.B
	T = mt.T
	C = mt.C
	L = mt.L
	F = mt.F
	def __init__(self):
		self.init = self.mt.init_genrand(19650218)
	def sanitize(self, x, w):
		assert isinstance(x, (int, bytes, str))
		if isinstance(x, int):
			assert 0 <= x < 2**w
			x = "".join([str(x >> i & 1) for i in range(w)])
		elif isinstance(x, bytes):
			assert len(x) == w
			w *= 8
			x = "".join([str(x[i >> 3] >> i % 8 & 1) for i in range(w)])
		assert len(x) == w
		assert all(c in "01?" for c in x)
		return x
	def init_twister(self, init_index):
		assert 0 <= init_index <= self.N
		bv = python_random_breaker.make_bit_vector([self.W] * self.N)
		self.init_index = init_index
		self.twister = self.mt(bv, self.init_index)
		self.solver = self.linear_equation_solver_GF2(self.N * self.W)
	def init_twister_after_seeding(self):
		self.init_twister(self.N)
		# https://github.com/python/cpython/blob/23362f8c301f72bbf261b56e1af93e8c52f5b6cf/Modules/_randommodule.c#L227
		# state[0] is 0x80000000U after seeding
		for i in range(self.W):
			assert self.solver.add_equation_if_consistent(1 << i, 1 if i == self.W - 1 else 0)
	# Given a linear combination of bits of current states described by `equation`, returns the equivalent linear combination of the original state
	def get_equation_on_current_state(self, equation):
		assert hasattr(self, "twister")
		assert 0 <= equation < 2**(self.N * self.W)
		eqs = 0
		for i in range(self.N):
			for j in range(self.W):
				if equation >> self.W * i + j & 1:
					eqs ^= self.twister.state[i][j][0] # There is no flip term
		return eqs
	def add_equation_on_current_state(self, equation, output):
		assert hasattr(self, "twister")
		assert 0 <= equation < 2**(self.N * self.W) and 0 <= output <= 1
		assert self.solver.add_equation_if_consistent(self.get_equation_on_current_state(equation), output)
	def add_equation(self, equation, output):
		assert hasattr(self, "twister")
		assert 0 <= equation < 2**(self.N * self.W) and 0 <= output <= 1
		assert self.solver.add_equation_if_consistent(equation, output)
	# if x is None, it returns the equation for output of python random getrandbits(32)
	# if x is an integer, it behaves as if it read the output of python random getrandbits(32)
	# if x is a string, it must of length self.W consisting of characters in "01?"
	def setrand_uint(self, x = None):
		assert hasattr(self, "twister")
		if x == None:
			return self.twister.genrand_uint()
		assert isinstance(x, (int, str))
		x = self.sanitize(x, self.W)
		eqs = self.twister.genrand_uint()
		for i in range(self.W):
			if x[i] != '?':
				assert self.solver.add_equation_if_consistent(eqs[i], int(x[i]))
	# if x is None, it returns the equation for output of python random getrandbits(n)
	# if x is an integer, it behaves as if it read the output of python random getrandbits(n)
	# if x is a string, it must be of length n consisting of characters in "01?"
	def setrandbits(self, n, x = None):
		assert hasattr(self, "twister")
		if x == None:
			return self.twister.getrandbits(n)
		assert isinstance(x, (int, str))
		x = self.sanitize(x, n)
		eqs = self.twister.getrandbits(n)
		for i in range(n):
			if x[i] != '?':
				assert self.solver.add_equation_if_consistent(eqs[i], int(x[i]))
	# if x is None, it returns the equation for output of python random randbytes(n)
	# if x is an integer, it behaves as if it read the output of python random randbytes(n)
	# if x is a string, it must be of length 8 * n consisting of characters in "01?"
	def setrandbytes(self, n, x = None):
		assert hasattr(self, "twister")
		if x == None:
			return self.twister.getrandbytes(n)
		assert isinstance(x, (bytes, str))
		x = self.sanitize(x, n)
		eqs = self.twister.getrandbytes(n)
		for i in range(8 * n):
			if x[i] != '?':
				assert self.solver.add_equation_if_consistent(eqs[i], int(x[i]))
	# if x is None, it returns the equation for output of python random random() * 2**53, which is an integer in range [0, 2**53)
	# if x is a float, it behaves as if it read the output of python random random()
	# if x is an integer, it behaves as if it read the output of python random random() * 2**53, which is an integer in range [0, 2**53)
	# if x is a string, it must be of length 53 consisting of characters in "01?"
	def setrandom(self, x = None):
		assert hasattr(self, "twister")
		if x == None:
			return self.twister.random()
		if isinstance(x, float):
			x = int(x * 2**53)
		if isinstance(x, int):
			assert 0 <= x < 2**53
		x = self.sanitize(x, 53)
		eqs = self.twister.random()
		for i in range(53):
			if x[i] != '?':
				assert self.solver.add_equation_if_consistent(eqs[i], int(x[i]))
	def rank(self):
		assert hasattr(self, "twister")
		return self.solver.rank()
	def nullity(self):
		assert hasattr(self, "twister")
		return self.solver.nullity()
	def uint_call_count(self):
		assert hasattr(self, "twister")
		return self.twister.uint_call_count()
	def recover_all_twister_states(self):
		assert hasattr(self, "twister")
		print(f"[INFO] <python_random_breaker> {2**self.nullity()} possible twister states")
		states = []
		for assignment in self.solver.all_solutions():
			states.append((3, tuple([assignment >> self.W * i & self.D for i in range(self.N)] + [self.init_index]), None))
		return states
	def recover_all_initial_rngs(self):
		assert hasattr(self, "twister")
		import random
		states = self.recover_all_twister_states()
		return [random.Random(state) for state in states]
	def recover_all_final_rngs(self):
		assert hasattr(self, "twister")
		rngs = self.recover_all_initial_rngs()
		for rng in rngs:
			for _ in range(self.uint_call_count()):
				rng.getrandbits(32)
		return rngs
	# key is a 32-bit integer array of 1 <= length <= 622
	def recover_all_small_keys_from_state(self, full_state):
		full_state = list(full_state[1])
		assert len(full_state) == self.N + 1 and full_state[0] == 0x80000000 and full_state[self.N] == self.N
		state = full_state[:]
		def rewind(left, cur, si):
			return (cur + si ^ (left ^ left >> 30) * 1566083941) & self.D
		def advance_key(left, cur, kx, ki):
			return (cur ^ (left ^ left >> 30) * 1664525) + kx + ki & self.D
		def recover_key(left, up, cur):
			return cur - (up ^ (left ^ left >> 30) * 1664525) & self.D
		si = 2
		state[0] = state[self.N - 1]
		for _ in range(self.N - 1):
			si = (si - 2) % (self.N - 1) + 1
			state[si] = rewind(state[si - 1], state[si], si)
			if si == self.N - 1:
				state[0] = state[self.N - 1]
		duplciated_key = [0] * self.N
		for si in range(3, self.N):
			duplciated_key[si] = recover_key(state[si - 1], self.init[si], state[si])
		keys = []
		for key_len in range(1, self.N - 2):
			if duplciated_key[3:-key_len] == duplciated_key[3 + key_len:]:
				key = [0] * key_len
				for si in range(3, 3 + key_len):
					key[(si - 1) % key_len] = duplciated_key[si] - (si - 1) % key_len & self.D
				if (key_len == 1 or key[-1] > 0) and self.mt.key_to_state(key) == full_state:
					keys.append(key)
		key_len = self.N - 2
		key = [0] * key_len
		for si in range(3, self.N):
			key[(si - 1) % key_len] = recover_key(state[si - 1], self.init[si], state[si]) - (si - 1) % key_len & self.D
		key[1] = recover_key(advance_key(self.init[0], self.init[1], key[0], 0), self.init[2], state[2]) - 1 & self.D
		if key[-1] > 0 and self.mt.key_to_state(key) == full_state:
			keys.append(key)
		return keys
	# key is a 32-bit integer array
	# len(key_head) must be a multiple of 623
	# if key_len <= 623, key_head and key_tail are []
	# if key_len > 623, len(key_head) + 623 + len(key_tail) == key_len
	# Note that
	# - For key_len = 623, there could be lots of solutions differing only at index 0 and 1
	# - For key_len != 623, there are at most 1 key
	# Note that key_len = 623 will take very long time to enumerate all solutions if filter_lowest_64_bit is not manually set and ignore_lowest_64_bit is False
	def recover_all_keys_from_state(self, full_state, key_len, key_head = [], key_tail = [], filter_lowest_64_bit = lambda _: True, ignore_lowest_64_bit = False):
		full_state = list(full_state[1])
		assert len(full_state) == self.N + 1 and full_state[0] == 0x80000000 and full_state[self.N] == self.N
		assert 1 <= key_len
		assert len(key_head) % (self.N - 1) == 0
		assert key_len < self.N and key_head == key_tail == [] or key_len >= self.N and len(key_head) + self.N - 1 + len(key_tail) == key_len
		assert all(0 <= x < 2**32 for x in key_head)
		assert all(0 <= x < 2**32 for x in key_tail)
		def rewind(left, cur, si):
			return (cur + si ^ (left ^ left >> 30) * 1566083941) & self.D
		def advance_key(left, up, kx, ki):
			return (up ^ (left ^ left >> 30) * 1664525) + kx + ki & self.D
		def rewind_key(left, cur, kx, ki):
			return (cur - kx - ki ^ (left ^ left >> 30) * 1664525) & self.D
		def recover_key(left, up, cur, ki):
			return cur - ki - (up ^ (left ^ left >> 30) * 1664525) & self.D
		def get_lowest_64_bit(key):
			return key[0] | key[1] << self.W if len(key) >= 2 else key[0]
		init = self.init[:]
		for ki, x in enumerate(key_head):
			si = ki % (self.N - 1) + 1
			init[si] = advance_key(init[si - 1], init[si], x, ki)
			if si == self.N - 1:
				init[0] = init[self.N - 1]
		state = full_state[:]
		si = max(self.N, key_len) % (self.N - 1) + 1
		state[0] = state[self.N - 1]
		for _ in range(self.N - 1):
			si = (si - 2) % (self.N - 1) + 1
			state[si] = rewind(state[si - 1], state[si], si)
			if si == self.N - 1:
				state[0] = state[self.N - 1]
		ki = max(self.N, key_len) % key_len
		keys = []
		if key_len >= self.N:
			for kx in reversed(key_tail):
				si = (si - 2) % (self.N - 1) + 1
				ki = (ki - 1) % key_len
				state[si] = rewind_key(state[si - 1], state[si], kx, ki)
				if si == self.N - 1:
					state[0] = state[self.N - 1]
			assert si == 1
			key = key_head[:] + [0] * (self.N - 1) + key_tail[:]
			for si in range(1, self.N):
				key[len(key_head) + si - 1] = recover_key(state[si - 1] if si >= 2 else init[0], init[si], state[si], len(key_head) + si - 1)
			if key[-1] > 0 and filter_lowest_64_bit(get_lowest_64_bit(key)):
				assert self.mt.key_to_state(key) == full_state
				keys.append(key)
		else:
			key = [0] * key_len
			for si in range(max(3, self.N - key_len), self.N):
				key[(si - 1) % key_len] = recover_key(state[si - 1], init[si], state[si], (si - 1) % key_len)
			if key_len != 1 and key[-1] == 0:
				return []
			for si in range(3, max(3, self.N - key_len)):
				if key[(si - 1) % key_len] != recover_key(state[si - 1], init[si], state[si], (si - 1) % key_len):
					return []
			if ignore_lowest_64_bit:
				keys.append(key)
			elif key_len <= self.N - 3:
				if filter_lowest_64_bit(get_lowest_64_bit(key)) and self.mt.key_to_state(key) == full_state:
					keys.append(key)
			elif key_len == self.N - 2:
				key[1] = recover_key(advance_key(init[0], init[1], key[0], 0), init[2], state[2], 1)
				if filter_lowest_64_bit(get_lowest_64_bit(key)) and self.mt.key_to_state(key) == full_state:
					keys.append(key)
			else:
				# There could be O(sqrt(self.W)) solutions without filter, which could be very slow to process
				c0 = (init[1] ^ (init[0] ^ init[0] >> 30) * 1664525) & self.D
				c1 = (state[0] ^ state[0] >> 30) * 1664525 & self.D
				key0s = [0]
				for bit in range(self.D.bit_length()):
					key0s_next = []
					for key0 in key0s:
						for d in range(2):
							key0_next = key0 | d << bit
							if (c0 + key0_next ^ c1) + key0_next & (1 << bit + 1) - 1 == state[1] & (1 << bit + 1) - 1:
								key0s_next.append(key0_next)
					key0s = key0s_next
				for key0 in key0s:
					key1 = recover_key(c0 + key0 & self.D, init[2], state[2], 1)
					if filter_lowest_64_bit(key0 | key1 << self.W):
						keys.append([key0, key1] + key[2:])
				assert all(self.mt.key_to_state(key) == full_state for key in keys)
		return keys
	# recover all possible  integer seeds whose bit_length is in range [0, 622 * 32] or bit_len_range
	def recover_all_small_integer_seeds_from_state(self, full_state, bit_len_range = None):
		import random
		if bit_len_range == None:
			bit_len_range = (0, (self.N - 2) * self.W)
		elif isinstance(bit_len_range, int):
			bit_len_range = (bit_len_range, bit_len_range)
		assert 0 <= bit_len_range[0] <= bit_len_range[1] <= (self.N - 2) * self.W
		seeds = []
		for key in self.recover_all_small_keys_from_state(full_state):
			if not (max(1, (bit_len_range[0] + self.W - 1) // self.W) <= len(key) <= max(1, (bit_len_range[1] + self.W - 1) // self.W)):
				continue
			seed = 0
			for x in reversed(key):
				seed = seed << self.W | x
			if not (bit_len_range[0] <= seed.bit_length() <= bit_len_range[1]):
				continue
			assert random.Random(seed).getstate() == full_state
			seeds.append(seed)
		return seeds
	# bit_len is seed.bit_length()
	# head_bit_len must be a multiple of 623 * 32
	# let tail_bit_len = max(0, bit_len - head_bit_len - 623 * 32)
	# seed_head is seed & 2**head_bit_len - 1
	# seed_tail is seed >> head_bit_len + 623 * 32
	def recover_all_integer_seeds_from_state(self, full_state, bit_len, head_bit_len = 0, seed_head = 0, seed_tail = 0, filter_lowest_64_bit = lambda _: True):
		import random
		tail_bit_len = max(0, bit_len - head_bit_len - (self.N - 1) * 32)
		assert 0 <= head_bit_len <= bit_len and 0 <= seed_head < 2**head_bit_len
		assert 0 <= tail_bit_len <= bit_len and 0 <= seed_tail < 2**tail_bit_len
		assert head_bit_len % ((self.N - 1) * self.W) == 0
		key_len = max(1, (bit_len + self.W - 1) // self.W)
		key_head, key_tail = [], []
		if bit_len > (self.N - 1) * self.W:
			assert head_bit_len + (self.N - 1) * self.W <= bit_len
			for bit in range(0, head_bit_len, self.W):
				key_head.append(seed_head >> bit & self.D)
			for bit in range(head_bit_len + (self.N - 1) * self.W, bit_len, self.W):
				key_tail.append(seed_tail >> bit - head_bit_len - (self.N - 1) * self.W & self.D)
		seeds = []
		for key in self.recover_all_keys_from_state(full_state, key_len, key_head, key_tail, filter_lowest_64_bit):
			seed = 0
			for x in reversed(key):
				seed = seed << self.W | x
			assert filter_lowest_64_bit(seed % 2**64)
			if seed.bit_length() != bit_len:
				continue
			assert random.Random(seed).getstate() == full_state
			seeds.append(seed)
		return seeds
	# https://github.com/python/cpython/blob/main/Lib/random.py#L154-L167
	# Byte seed length must be in range [0, 622 * 4 - 64]
	def recover_all_small_byte_seeds_from_state(self, full_state, byte_len_range = None):
		import random
		from hashlib import sha512
		if byte_len_range == None:
			byte_len_range = (0, (self.N - 2) * self.W // 8 - 64)
		elif isinstance(byte_len_range, int):
			byte_len_range = (byte_len_range, byte_len_range)
		assert 0 <= byte_len_range[0] <= byte_len_range[1] <= (self.N - 2) * self.W // 8 - 64
		seeds = []
		for key in self.recover_all_small_keys_from_state(full_state):
			if not ((512 + self.W - 1) // self.W <= len(key) <= (8 * byte_len_range[1] + 512 + self.W - 1) // self.W):
				continue
			seed = bytes([x >> 8 * i & 0xff for x in reversed(key) for i in range(3, -1, -1)])
			i = 0
			while len(seed) - i > 64 and seed[i] == 0:
				i += 1
			seed = seed[i:]
			while len(seed) - 64 <= byte_len_range[1]:
				if byte_len_range[0] <= len(seed) - 64 and sha512(seed[:-64]).digest()[:-8] == seed[-64:-8]:
					assert random.Random(seed[:-64]).getstate() == full_state
					seeds.append(seed[:-64])
				seed = bytes(1) + seed
		return seeds
	# seed_head is seed[:-(623 * 4 - 64)]
	def recover_all_byte_seeds_from_state(self, full_state, byte_len, seed_head = bytes()):
		import random
		from hashlib import sha512
		assert 0 <= byte_len
		assert all(0 <= x < 256 for x in seed_head)
		if byte_len <= (self.N - 1) * self.W // 8 - 64:
			assert seed_head == bytes()
			key_tail = []
		else:
			assert 8 * byte_len + 512 == (self.N - 1) * self.W + 8 * len(seed_head)
			key_tail = []
			for i in range(len(seed_head), 0, -4):
				x = 0
				for j in range(0, min(4, i)):
					x |= seed_head[i - 1 - j] << 8 * j
				key_tail.append(x)
			while len(key_tail) > 0 and key_tail[-1] == 0:
				key_tail.pop()
		seeds = []
		def solve_for_key(key):
			seed = bytes([x >> 8 * i & 0xff for x in reversed(key) for i in range(3, -1, -1)])
			i = 0
			while len(seed) - i > 64 and seed[i] == 0:
				i += 1
			seed = seed[i:]
			if len(seed) - 64 <= byte_len:
				seed = bytes(byte_len - len(seed) + 64) + seed
				assert len(seed) == byte_len + 64
				if sha512(seed[:-64]).digest()[:-8] == seed[-64:-8]:
					assert random.Random(seed[:-64]).getstate() == full_state
					seeds.append(seed[:-64])
		if len(key_tail) > 0:
			for key in self.recover_all_keys_from_state(full_state, len(key_tail) + self.N - 1, [], key_tail, ignore_lowest_64_bit = True):
				solve_for_key(key)
		else:
			for key in self.recover_all_small_keys_from_state(full_state):
				solve_for_key(key)
			for key in self.recover_all_keys_from_state(full_state, self.N - 1, ignore_lowest_64_bit = True):
				solve_for_key(key)
		return seeds
	# From https://stackered.com/blog/python-random-prediction
	def untemper(self, x):
		def unshift_right(x, shift):
			assert shift > 0
			res = x
			for i in range(0, self.W, shift):
				res = x ^ res >> shift
			return res
		def unshift_left(x, shift, mask):
			assert shift > 0
			res = x
			for i in range(0, self.W, shift):
				res = x ^ res << shift & mask
			return res
		x = unshift_right(x, self.L)
		x = unshift_left(x, self.T, self.C)
		x = unshift_left(x, self.S, self.B)
		x = unshift_right(x, self.U)
		return x
	# From https://stackered.com/blog/python-random-prediction
	# Note that the first state value is never used except for its MSB
	def untwist(self, state):
		assert len(state) == self.N
		state = state[:]
		def invert_step(x):
			mti1 = x >> self.R
			if mti1:
				x ^= self.A
			return x << 1 & 2**self.W - 2**self.R, mti1 + (x << 1 & 2**self.R - 1)
		prev_state = [0] * self.N
		for i in reversed(range(self.N)):
			upper, lower = invert_step(state[i - (self.N - self.M)] ^ state[i] if i >= self.N - self.M else prev_state[i + self.M] ^ state[i])
			prev_state[i] |= upper
			if i == self.N - 1:
				state[0] = state[0] & 2**self.W - 2**self.R | lower
			else:
				prev_state[i + 1] |= lower
		# The LSBs of prev_state[0] do not matter, they are 0 here
		return prev_state[:]
	# Returns a set of output indices needed in order to recover key of size key_len
	# if is_exact is false, it askes for 2 less outputs, but there could be two possible seeds
	# key_len cannot exceed 624 - 397 - 2 - is_exact
	# Note that there are many other index sets which you can recover the seed, and it's possible to solve for bigger key_len
	# This method is only there to help deciding indices for recover_all_keys_from_few_outputs on basic cases
	def get_required_output_indices_for_key_recovery(self, key_len, is_exact = False):
		assert 1 <= key_len <= self.N - self.M - 2 - is_exact
		return list(range(key_len + 2 + is_exact)) + list(range(self.N - self.M, self.N - self.M + key_len + 2 + is_exact))
	# Accept outputs of python rng getrandbits(32) at indices given by get_required_output_indices_for_key_recovery
	# if is_exact is false, it askes for 2 less outputs, but there could be two possible seeds
	# Note that there are many other index sets which you can recover the seed, and it's possible to solve for bigger key_len
	def recover_all_keys_from_few_outputs(self, key_len, outputs, is_exact = False):
		assert 0 <= key_len <= self.N - self.M - 2 - is_exact
		indices = self.get_required_output_indices_for_key_recovery(key_len, is_exact)
		outputs = [self.untemper(x) for x in outputs]
		assert len(indices) == len(outputs)
		def invert_step(x):
			mti1 = x >> self.R
			if mti1:
				x ^= self.A
			return x << 1 & 2**self.W - 2**self.R, mti1 + (x << 1 & 2**self.R - 1)
		def recover_key(left, mid, right, si, ki):
			left = (mid + si - 1 ^ (left ^ left >> 30) * 1566083941) & self.D
			right = (right + si ^ (mid ^ mid >> 30) * 1566083941) & self.D
			return right - ki - (self.init[si] ^ (left ^ left >> 30) * 1664525) & self.D
		state = [0] * self.N
		for si in range(key_len + 2 + is_exact):
			upper, lower = invert_step(outputs[si] ^ outputs[si + key_len + 2 + is_exact])
			state[si + self.N - self.M] |= upper
			state[si + self.N - self.M + 1] |= lower
		keys = []
		for _ in range(2 - is_exact):
			key = [0] * key_len
			for si in range(self.N - self.M + 3, self.N - self.M + 3 + key_len):
				ki = (si - 1) % key_len
				key[ki] = recover_key(state[si - 2], state[si - 1], state[si], si, ki)
			if key_len == 1 or key[-1] > 0:
				real_outputs = self.mt.key_to_state(key)
				self.mt.twist(self.mt, real_outputs)
				if all(real_outputs[i] == x for i, x in zip(indices, outputs)):
					keys.append(key)
			state[key_len + 2 + is_exact + self.N - self.M] ^= 2**self.W - 2**self.R
		return keys
	# Returns a set of output indices needed in order to recover bit_len integer seed
	# if is_exact is false, it askes for 2 less outputs, but there could be two possible seeds
	# bit_len cannot exceed (624 - 397 - 2 - is_exact) * 32
	# Note that there are many other index sets which you can recover the seed, and it's possible to solve for bigger bit_len
	def get_required_output_indices_for_integer_seed_recovery(self, bit_len, is_exact = False):
		assert 0 <= bit_len <= (self.N - self.M - 2 - is_exact) * self.W
		if bit_len <= 1:
			return []
		return self.get_required_output_indices_for_key_recovery((bit_len + self.W - 1) // self.W, is_exact)
	# Accept outputs of python rng getrandbits(32) at indices given by get_required_output_indices_for_integer_seed_recovery
	# if is_exact is false, it askes for 2 less outputs, but there could be two possible seeds
	# Note that there are many other index sets which you can recover the seed, and it's possible to solve for bigger bit_len
	def recover_all_integer_seeds_from_few_outputs(self, bit_len, outputs, is_exact = False):
		import random
		assert 0 <= bit_len <= (self.N - self.M - 2 - is_exact) * self.W
		indices = self.get_required_output_indices_for_integer_seed_recovery(bit_len, is_exact)
		assert len(indices) == len(outputs)
		if bit_len <= 1:
			return [bit_len]
		key_len = (bit_len + self.W - 1) // self.W
		seeds = []
		for key in self.recover_all_keys_from_few_outputs(key_len, outputs, is_exact):
			seed = 0
			for x in reversed(key):
				seed = seed << self.W | x
			rng = random.Random(seed)
			real_outputs = [rng.getrandbits(self.W) for _ in range(self.N)]
			for i, x in zip(indices, outputs):
				assert real_outputs[i] == x
			seeds.append(seed)
		for seed in seeds:
			rng = random.Random(seed)
			real_outputs = [rng.getrandbits(self.W) for _ in range(self.N)]
			assert all(real_outputs[i] == x for i, x in zip(indices, outputs))
		return seeds
	# Returns a set of output indices needed in order to recover byte_len byte seed
	# if is_exact is false, it askes for 2 less outputs, but there could be two possible seeds
	# byte_len cannot exceed (624 - 397 - 2 - is_exact) * 4 - 64
	# Note that there are many other index sets which you can recover the seed, and it's possible to solve for bigger byte_len
	def get_required_output_indices_for_byte_seed_recovery(self, byte_len, is_exact = False):
		assert 0 <= byte_len <= (self.N - self.M - 2 - is_exact) * self.W // 8 - 64
		return self.get_required_output_indices_for_key_recovery((8 * byte_len + self.W - 1) // self.W + 16, is_exact)
	# Accept outputs of python rng getrandbits(32) at indices given by get_required_output_indices_for_byte_seed_recovery
	# if is_exact is false, it askes for 2 less outputs, but there could be two possible seeds
	# Note that there are many other index sets which you can recover the seed, and it's possible to solve for bigger byte_len
	# WARNING: this method assumes the leading byte of seed is non-zero
	def recover_all_byte_seeds_from_few_outputs(self, byte_len, outputs, is_exact = False):
		import random
		from hashlib import sha512
		assert 0 <= byte_len <= (self.N - self.M - 2 - is_exact) * self.W // 8 - 64
		indices = self.get_required_output_indices_for_byte_seed_recovery(byte_len, is_exact)
		assert len(indices) == len(outputs)
		if byte_len == 0:
			return [b""]
		key_len = (8 * byte_len + self.W - 1) // self.W + 16
		seeds = []
		for key in self.recover_all_keys_from_few_outputs(key_len, outputs, is_exact):
			seed = bytes([x >> 8 * i & 0xff for x in reversed(key) for i in range(3, -1, -1)])
			i = 0
			while len(seed) - i > 64 and seed[i] == 0:
				i += 1
			seed = seed[i:]
			if sha512(seed[:-64]).digest()[:-8] == seed[-64:-8]:
				seeds.append(seed[:-64])
		for seed in seeds:
			rng = random.Random(seed)
			real_outputs = [rng.getrandbits(self.W) for _ in range(self.N)]
			assert all(real_outputs[i] == x for i, x in zip(indices, outputs))
		return seeds

if __name__ == "__main__":
	import random

	def test_state_recovery():
		rng = random.Random()
		obj_state = rng.getstate()
		breaker = python_random_breaker()
		breaker.init_twister_after_seeding()
		for _ in range(180):
			breaker.setrand_uint(rng.getrandbits(32))
			breaker.setrandbits(17, rng.getrandbits(17))
			breaker.setrandbits(37, rng.getrandbits(37))
			breaker.setrandbytes(5, rng.randbytes(5))
			breaker.setrandom(rng.random())
			print(f"[test_state_recovery] iteration #{_} nullity {breaker.nullity()}")
		assert [obj_state] == breaker.recover_all_twister_states()
		print(f"[test_state_recovery] Ok")

	def test_small_integer_seed_recovery():
		for bit_len in list(range(0, 100)) + list(range(19904 - 100, 19904 + 1)):
			while True:
				seed = random.getrandbits(bit_len)
				if seed.bit_length() == bit_len:
					break
			print(f"[test_small_integer_seed_recovery] Testing bit_len {bit_len}")
			rng = random.Random()
			rng.seed(seed)
			breaker = python_random_breaker()
			assert seed in breaker.recover_all_small_integer_seeds_from_state(rng.getstate(), bit_len)
			assert seed in breaker.recover_all_small_integer_seeds_from_state(rng.getstate())
		print(f"[test_small_integer_seed_recovery] Ok")

	def test_integer_seed_recovery():
		for bit_len in list(range(0, 623)) + list(range(19904 - 1000, 19904 + 1000)) + list(range(10**5, 10**5 + 1000)):
			while True:
				seed = random.getrandbits(bit_len)
				if seed.bit_length() == bit_len:
					break
			rng = random.Random()
			rng.seed(seed)
			breaker = python_random_breaker()
			for head_bit_len in range(0, min(623 * 32 * 3 + 1, max(0, bit_len - 623 * 32) + 1), 623 * 32):
				print(f"[test_integer_seed_recovery] Testing bit_len {bit_len} head_bit_len {head_bit_len}")
				assert seed in breaker.recover_all_integer_seeds_from_state(rng.getstate(), bit_len, head_bit_len, seed & 2**head_bit_len - 1, seed >> head_bit_len + 623 * 32, filter_lowest_64_bit = lambda x: x == seed % 2**64)
		print(f"[test_integer_seed_recovery] Ok")

	def test_small_byte_seed_recovery():
		for byte_len in list(range(0, 25)) + list(range(2488 - 64 - 25, 2488 - 64 + 1)):
			seed = random.randbytes(byte_len)
			for _ in range(2):
				print(f"[test_small_byte_seed_recovery] Testing byte_len {byte_len}{' zero leading bytes' if _ else ''}")
				rng = random.Random()
				rng.seed(seed)
				breaker = python_random_breaker()
				assert seed in breaker.recover_all_small_byte_seeds_from_state(rng.getstate(), byte_len)
				assert seed in breaker.recover_all_small_byte_seeds_from_state(rng.getstate())
				seed = bytes(byte_len // 2) + seed[byte_len // 2:]
		print(f"[test_small_byte_seed_recovery] Ok")

	def test_byte_seed_recovery():
		for byte_len in list(range(0, 100)) + list(range(2488 - 64 - 50, 2488 - 64 + 50)) + list(range(10**5 // 8, 10**5 // 8 + 100)):
			seed = random.randbytes(byte_len)
			for _ in range(2):
				print(f"[test_byte_seed_recovery] Testing byte_len {byte_len}{' zero leading bytes' if _ else ''}")
				rng = random.Random()
				rng.seed(seed)
				breaker = python_random_breaker()
				assert seed in breaker.recover_all_byte_seeds_from_state(rng.getstate(), byte_len, seed[:-(623 * 4 - 64)])
				seed = bytes(byte_len // 2) + seed[byte_len // 2:]
		print(f"[test_byte_seed_recovery] Ok")

	def test_untwist():
		rng = random.Random()
		obj_state = list(rng.getstate()[1][:-1])
		for _ in range(5):
			for _ in range(624):
				rng.getrandbits(32)
		breaker = python_random_breaker()
		state = [breaker.untemper(rng.getrandbits(32)) for _ in range(624)]
		for _ in range(6):
			state = breaker.untwist(state)
		assert obj_state == state
		print(f"[test_untwist] Ok")

	def test_recover_all_integer_seeds_from_few_outputs():
		for bit_len in list(range(0, 100)) + list(range(7200 - 100, 7200 + 1)):
			while True:
				seed = random.getrandbits(bit_len)
				if seed.bit_length() == bit_len:
					break
			rng = random.Random()
			rng.seed(seed)
			outputs = [rng.getrandbits(32) for _ in range(624)]
			breaker = python_random_breaker()
			for is_exact in range(2):
				if bit_len > (624 - 397 - 2 - is_exact) * 32:
					continue
				print(f"[test_recover_all_integer_seeds_from_few_outputs] Testing bit_len {bit_len} {'exact' if is_exact else 'non-exact'}")
				cur_outputs = [outputs[i] for i in breaker.get_required_output_indices_for_integer_seed_recovery(bit_len, is_exact)]
				if is_exact:
					assert [seed] == breaker.recover_all_integer_seeds_from_few_outputs(bit_len, cur_outputs, True)
				else:
					assert seed in breaker.recover_all_integer_seeds_from_few_outputs(bit_len, cur_outputs, False)
		print(f"[test_recover_all_integer_seeds_from_few_outputs] Ok")

	def test_recover_all_byte_seeds_from_few_outputs():
		for byte_len in list(range(0, 25)) + list(range(836 - 25, 836 + 1)):
			while True:
				seed = random.randbytes(byte_len)
				if len(seed) == 0 or seed[0] > 0:
					break
			rng = random.Random()
			rng.seed(seed)
			outputs = [rng.getrandbits(32) for _ in range(624)]
			breaker = python_random_breaker()
			for is_exact in range(2):
				if byte_len > (624 - 397 - 2 - is_exact) * 4 - 64:
					continue
				print(f"[test_recover_all_byte_seeds_from_few_outputs] Testing byte_len {byte_len} {'exact' if is_exact else 'non-exact'}")
				cur_outputs = [outputs[i] for i in breaker.get_required_output_indices_for_byte_seed_recovery(byte_len, is_exact)]
				if is_exact:
					assert [seed] == breaker.recover_all_byte_seeds_from_few_outputs(byte_len, cur_outputs, True)
				else:
					assert seed in breaker.recover_all_byte_seeds_from_few_outputs(byte_len, cur_outputs, False)

	test_state_recovery()
	test_small_integer_seed_recovery()
	test_integer_seed_recovery()
	test_small_byte_seed_recovery()
	test_byte_seed_recovery()
	test_untwist()
	test_recover_all_integer_seeds_from_few_outputs()
	test_recover_all_byte_seeds_from_few_outputs()
