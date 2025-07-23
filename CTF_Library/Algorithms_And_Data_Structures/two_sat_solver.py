class two_sat_solver:
	def __init__(self, n):
		self.n = n
		self.adj = [[] for _ in range(2 * n)]
		self.value = []
	def add_variable(self):
		self.adj.append([])
		self.adj.append([])
		self.n += 1
		return self.n - 1
	def either(self, u, v):
		u = max(2 * u, -1 - 2 * u)
		v = max(2 * v, -1 - 2 * v)
		self.adj[u].append(v ^ 1)
		self.adj[v].append(u ^ 1)
	def implies(self, u, v):
		self.either(~u, v)
	def equals(self, u, v):
		self.either(~u, v)
		self.either(u, ~v)
	def differs(self, u, v):
		self.either(u, v)
		self.either(~u, ~v)
	def set_value(self, u, x = True):
		if x:
			self.either(u, u)
		else:
			self.either(~u, ~u)
	def at_most_one(self, arr):
		if len(arr) <= 1:
			return
		cur = ~arr[0]
		for i in range(2, len(arr)):
			next_var = self.add_variable()
			self.either(cur, ~arr[i])
			self.either(cur, next_var)
			self.either(~arr[i], next_var)
			cur = ~next_var
		self.either(cur, ~arr[1])
	def _dfs(self, u):
		self.time += 1
		low = self.time
		self.val[u] = self.time
		self.z.append(u)
		for v in self.adj[u]:
			if self.comp[v] == -1:
				if self.val[v] == 0:
					low = min(low, self._dfs(v))
				else:
					low = min(low, self.val[v])
		self.time += 1
		if low == self.val[u]:
			while True:
				v = self.z.pop()
				self.comp[v] = self.comp_cnt
				if self.value[v >> 1] == -1:
					self.value[v >> 1] = v & 1
				if v == u:
					break
			self.comp_cnt += 1
		self.val[u] = low
		return low
	def solve(self):
		self.value = [-1] * self.n
		self.val = [0] * (2 * self.n)
		self.comp = [-1] * (2 * self.n)
		self.z = []
		self.time = 0
		self.comp_cnt = 0
		for u in range(2 * self.n):
			if self.comp[u] == -1:
				self._dfs(u)
		for u in range(self.n):
			if self.comp[u << 1] == self.comp[u << 1 ^ 1]:
				return False
		return True
