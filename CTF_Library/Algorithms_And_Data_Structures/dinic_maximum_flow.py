class dinic_maximum_flow:
	def __init__(self, F):
		from CTF_Library.Algorithms_And_Data_Structures.flow_network import flow_network
		assert isinstance(F, flow_network)
		self.eps = 0
		self.inf = 10**18
		self.F = F
		self.ptr = [0] * F.n
		self.level = [0] * F.n
		self.q = [0] * F.n
	def bfs(self, source: int, sink: int) -> bool:
		self.level = [-1] * self.F.n
		self.q[0] = sink
		self.level[sink] = 0
		beg, end = 0, 1
		while beg < end:
			i = self.q[beg]
			beg += 1
			for ind in self.F.adj[i]:
				e = self.F.edge[ind]
				re = self.F.edge[ind ^ 1]
				if re.capacity - re.flow > self.eps and self.level[e.to] == -1:
					self.level[e.to] = self.level[i] + 1
					if e.to == source:
						return True
					self.q[end] = e.to
					end += 1
		return False
	def _dfs(self, u: int, w: int, sink: int) -> int:
		if u == sink:
			return w
		while self.ptr[u] >= 0:
			ind = self.F.adj[u][self.ptr[u]]
			e = self.F.edge[ind]
			if e.capacity - e.flow > self.eps and self.level[e.to] == self.level[u] - 1:
				flow = self._dfs(e.to, min(e.capacity - e.flow, w), sink)
				if flow > self.eps:
					self.F.add_flow(ind, flow)
					return flow
			self.ptr[u] -= 1
		return 0
	def maximum_flow(self, source: int, sink: int) -> int:
		assert 0 <= source < self.F.n and 0 <= sink < self.F.n
		flow = 0
		while self.bfs(source, sink):
			for i in range(self.F.n):
				self.ptr[i] = len(self.F.adj[i]) - 1
			while True:
				add = self._dfs(source, self.inf, sink)
				if add <= self.eps:
					break
				flow += add
		return flow
