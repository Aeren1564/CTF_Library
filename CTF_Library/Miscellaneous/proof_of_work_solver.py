# Solve PoW for https://goo.gle/kctf-pow
def solve_google_PoW(io):
	import subprocess
	print(f"[solve_google_PoW] Solving google PoW")
	head = io.readline()
	if head == b"== proof-of-work: enabled ==\n":
		assert io.readlines(2) == [
			b"please solve a pow first",
			b"You can run the solver with:"
		]
		cmd = io.readlineS().strip()
		print(f"[solve_google_PoW] Running command: {cmd}")
		io.sendlineafter(b"Solution? ", subprocess.check_output(
			cmd,
			shell = True,
			executable = "/bin/bash",
			stderr = subprocess.DEVNULL
		))
		assert io.readline() == b"Correct\n"
	elif head == b"== proof-of-work: disabled ==\n":
		pass
	else:
		assert False
	print(f"[solve_google_PoW] Done")
