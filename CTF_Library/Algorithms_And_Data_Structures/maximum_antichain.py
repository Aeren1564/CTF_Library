def maximum_antichain(n, edge, vertex_weight = []):
	from CTF_Library.Algorithms_And_Data_Structures.flow_network import flow_network
	from CTF_Library.Algorithms_And_Data_Structures.dinic_maximum_flow import dinic_maximum_flow
	assert n >= 1
	if not vertex_weight:
		vertex_weight = [1] * n
	assert min(vertex_weight) >= 0
	F = flow_network(2 * n + 2)
	idL = [0] * n
	idR = [0] * n
	for u in range(n):
		idL[u] = F.orient(2 * n, u, vertex_weight[u])
		idR[u] = F.orient(n + u, 2 * n + 1, vertex_weight[u])
	for u, v in edge:
		F.orient(u, n + v, 10**18)
	dinic_maximum_flow(F).maximum_flow(2 * n, 2 * n + 1)
	vis = [False] * (2 * n)
	def _dfs(u: int):
		vis[u] = True
		for id in F.adj[u]:
			v = F.edge[id].to
			if v >= 2 * n or vis[v]:
				continue
			if u < n:
				if (F.edge[idL[u]].saturated() and
					F.edge[idR[v - n]].saturated() and
					F.edge[idL[u]].flow == F.edge[id].flow and
					F.edge[id].flow == F.edge[idR[v - n]].flow):
					continue
			elif F.edge[id].flow == 0:
				continue
			_dfs(v)
	for u in range(n):
		if not vis[u] and not F.edge[idL[u]].saturated():
			_dfs(u)
	antichain = [u for u in range(n) if vis[u] and not vis[n + u]]
	return antichain
