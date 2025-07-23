class flow_network:
	class Edge:
		def __init__(self, from_, to, capacity, flow):
			self.from_ = from_
			self.to = to
			self.capacity = capacity
			self.flow = flow
		def saturated(self):
			eps = 0
			return self.capacity - self.flow <= eps
	def __init__(self, n: int):
		self.n = n
		self.adj = [[] for _ in range(n)]
		self.edge = []
	def orient(self, from_: int, to: int, cap: int) -> int:
		assert 0 <= min(from_, to) and max(from_, to) < self.n and cap >= 0
		ind = len(self.edge)
		self.adj[from_].append(ind)
		self.edge.append(self.Edge(from_, to, cap, 0))
		self.adj[to].append(ind + 1)
		self.edge.append(self.Edge(to, from_, 0, 0))
		return ind
	def add_flow(self, i: int, f: int):
		self.edge[i].flow += f
		self.edge[i ^ 1].flow -= f
