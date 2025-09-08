# Hint is a tuple of (message, iv, ciphertext) which are bytes of length 16
# padding_oracle(iv, ciphertext) checks whether the plaintext is padded
# if faulty, padding_oracle returns True on some instances where it should return False
# Returns a tuple of iv and ciphertext if not faulty, otherwise all possible such tuples
def forge_CBC_ciphertext_with_padding_oracle(plaintext : bytes, padding_oracle, hint = None, faulty = False, pool = list(range(2**8))):
	pool = list(sorted(set(map(int, pool))))
	assert 0 < len(pool) and 0 <= min(pool) and max(pool) < 2**8
	n, pad_len = len(plaintext), 16
	assert pad_len > 0 and n % pad_len == 0 and n > 0
	plaintext, ciphertext = list(plaintext), [0] * (n + pad_len)
	if hint is not None:
		hm, hiv, hct = hint
		assert isinstance(hm, bytes) and isinstance(hiv, bytes) and isinstance(hct, bytes)
		assert len(hm) == pad_len and len(hct) == pad_len and len(hiv) == pad_len
		for i in range(pad_len):
			ciphertext[n - pad_len + i] = hm[i] ^ hiv[i] ^ plaintext[n - pad_len + i]
			ciphertext[n + i] = hct[i]
	q = [ciphertext[:]]
	for i in reversed(range(n // pad_len - int(hint != None))):
		for j in reversed(range(pad_len)):
			print(f"[INFO] <forge_CBC_ciphertext_with_padding_oracle> Forging block {i} at index {j}")
			for k in range(j, pad_len):
				plaintext[pad_len * i + k] ^= pad_len - j ^ (pad_len - j - 1 if k > j else 0)
			q_next = []
			for ciphertext in q:
				print(f"[INFO] <forge_CBC_ciphertext_with_padding_oracle> {ciphertext = }")
				candidate = []
				for x in pool:
					ciphertext[pad_len * i + j] = x
					cur_ciphertext = ciphertext[: pad_len * i] + list(x ^ y for x, y in zip(plaintext[pad_len * i : pad_len * (i + 1)], ciphertext[pad_len * i : pad_len * (i + 1)])) + ciphertext[pad_len * (i + 1) : pad_len * (i + 2)]
					resp = padding_oracle(bytes(cur_ciphertext[: pad_len]), bytes(cur_ciphertext[pad_len :]))
					assert isinstance(resp, bool)
					if not resp:
						continue
					if j == pad_len - 1:
						plaintext[pad_len * i + j - 1] ^= 1
						cur_ciphertext = ciphertext[: pad_len * i] + list(x ^ y for x, y in zip(plaintext[pad_len * i : pad_len * (i + 1)], ciphertext[pad_len * i : pad_len * (i + 1)])) + ciphertext[pad_len * (i + 1) : pad_len * (i + 2)]
						resp = padding_oracle(bytes(cur_ciphertext[: pad_len]), bytes(cur_ciphertext[pad_len :]))
						plaintext[pad_len * i + j - 1] ^= 1
						assert isinstance(resp, bool)
						if not resp:
							continue
					candidate.append(x)
					if not faulty:
						break
				if not faulty and len(candidate) != 1:
					assert False, f"[ERROR] <forge_CBC_ciphertext_with_padding_oracle> Failed to forge block {i}, index {j}: unique candidate expected"
				for x in candidate:
					q_next.append(ciphertext[: pad_len * i + j] + [x] + ciphertext[pad_len * i + j + 1 :])
			q = q_next
		for k in range(pad_len):
			plaintext[pad_len * i + k] ^= pad_len
	res = [(bytes(ciphertext[: pad_len]), bytes(ciphertext[pad_len :])) for ciphertext in q]
	return res[0] if not faulty else res

# Hint is a tuple of (message, iv, ciphertext) which are bytes of length 16
# padding_oracle_request(iv, ciphertext) checks whether the plaintext is padded, whose result can be read from padding_oracle_read()
# if faulty, padding_oracle returns True on some instances where it should return False
# Returns a tuple of iv and ciphertext if not faulty, otherwise all possible such tuples
def forge_CBC_ciphertext_with_batched_padding_oracle(plaintext : bytes, padding_oracle_request, padding_oracle_read, batch_size = 2**8, hint = None, faulty = False, pool = list(range(2**8))):
	pool = list(sorted(set(map(int, pool))))
	assert 0 < len(pool) and 0 <= min(pool) and max(pool) < 2**8
	n, pad_len = len(plaintext), 16
	assert pad_len > 0 and n % pad_len == 0 and n > 0
	plaintext, ciphertext = list(plaintext), [0] * (n + pad_len)
	if hint is not None:
		hm, hiv, hct = hint
		assert isinstance(hm, bytes) and isinstance(hiv, bytes) and isinstance(hct, bytes)
		assert len(hm) == pad_len and len(hct) == pad_len and len(hiv) == pad_len
		for i in range(pad_len):
			ciphertext[n - pad_len + i] = hm[i] ^ hiv[i] ^ plaintext[n - pad_len + i]
			ciphertext[n + i] = hct[i]
	q = [ciphertext[:]]
	for i in reversed(range(n // pad_len - int(hint != None))):
		for j in reversed(range(pad_len)):
			print(f"[INFO] <forge_CBC_ciphertext_with_batched_padding_oracle> Forging block {i} at index {j}")
			for k in range(j, pad_len):
				plaintext[pad_len * i + k] ^= pad_len - j ^ (pad_len - j - 1 if k > j else 0)
			q_next = []
			for ciphertext in q:
				print(f"[INFO] <forge_CBC_ciphertext_with_batched_padding_oracle> {ciphertext = }")
				candidate = []
				for batch_start in range(0, len(pool), batch_size):
					for x in pool[batch_start : batch_start + batch_size]:
						ciphertext[pad_len * i + j] = x
						cur_ciphertext = ciphertext[: pad_len * i] + list(x ^ y for x, y in zip(plaintext[pad_len * i : pad_len * (i + 1)], ciphertext[pad_len * i : pad_len * (i + 1)])) + ciphertext[pad_len * (i + 1) : pad_len * (i + 2)]
						padding_oracle_request(bytes(cur_ciphertext[: pad_len]), bytes(cur_ciphertext[pad_len :]))
						if j == pad_len - 1:
							plaintext[pad_len * i + j - 1] ^= 1
							cur_ciphertext = ciphertext[: pad_len * i] + list(x ^ y for x, y in zip(plaintext[pad_len * i : pad_len * (i + 1)], ciphertext[pad_len * i : pad_len * (i + 1)])) + ciphertext[pad_len * (i + 1) : pad_len * (i + 2)]
							padding_oracle_request(bytes(cur_ciphertext[: pad_len]), bytes(cur_ciphertext[pad_len :]))
							plaintext[pad_len * i + j - 1] ^= 1
					for x in pool[batch_start : batch_start + batch_size]:
						resps = [padding_oracle_read()]
						assert isinstance(resps[-1], bool)
						if j == pad_len - 1:
							resps.append(padding_oracle_read())
							assert isinstance(resps[-1], bool)
						if all(resps):
							candidate.append(x)
					if not faulty and len(candidate) > 0:
						break
				if not faulty and len(candidate) != 1:
					assert False, f"[ERROR] <forge_CBC_ciphertext_with_batched_padding_oracle> Failed to forge block {i}, index {j}: unique candidate expected"
				for x in candidate:
					q_next.append(ciphertext[: pad_len * i + j] + [x] + ciphertext[pad_len * i + j + 1 :])
			q = q_next
		for k in range(pad_len):
			plaintext[pad_len * i + k] ^= pad_len
	res = [(bytes(ciphertext[: pad_len]), bytes(ciphertext[pad_len :])) for ciphertext in q]
	return res[0] if not faulty else res

# padding_oracle(iv, ciphertext) checks whether the plaintext is padded
# if faulty, padding_oracle returns True on some instances where it should return False
# Returns the plaintext if not faulty, otherwise all possible such plaintexts, such that CBC(plaintext, iv) = ciphertext
def forge_CBC_plaintext_with_padding_oracle(iv: bytes, ciphertext : bytes, padding_oracle, faulty = False, pool = list(range(2**8))):
	pool = list(sorted(set(map(int, pool))))
	assert 0 < len(pool) and 0 <= min(pool) and max(pool) < 2**8
	n, pad_len = len(ciphertext), 16
	assert pad_len > 0 and n % pad_len == 0 and n > 0
	ciphertext, plaintext = list(iv) + list(ciphertext), [0] * n
	q = [plaintext[:]]
	for i in reversed(range(n // pad_len)):
		for j in reversed(range(pad_len)):
			print(f"[INFO] <forge_CBC_plaintext_with_padding_oracle> Forging block {i} at index {j}")
			for k in range(j, pad_len):
				ciphertext[pad_len * i + k] ^= pad_len - j ^ (pad_len - j - 1 if k > j else 0)
			q_next = []
			for plaintext in q:
				print(f"[INFO] <forge_CBC_plaintext_with_padding_oracle> {plaintext = }")
				candidate = []
				for x in pool:
					plaintext[pad_len * i + j] = x
					cur_ciphertext = ciphertext[: pad_len * i] + list(x ^ y for x, y in zip(plaintext[pad_len * i : pad_len * (i + 1)], ciphertext[pad_len * i : pad_len * (i + 1)])) + ciphertext[pad_len * (i + 1) : pad_len * (i + 2)]
					resp = padding_oracle(bytes(cur_ciphertext[: pad_len]), bytes(cur_ciphertext[pad_len :]))
					assert isinstance(resp, bool)
					if not resp:
						continue
					if j == pad_len - 1:
						ciphertext[pad_len * i + j - 1] ^= 1
						cur_ciphertext = ciphertext[: pad_len * i] + list(x ^ y for x, y in zip(plaintext[pad_len * i : pad_len * (i + 1)], ciphertext[pad_len * i : pad_len * (i + 1)])) + ciphertext[pad_len * (i + 1) : pad_len * (i + 2)]
						ciphertext[pad_len * i + j - 1] ^= 1
						resp = padding_oracle(bytes(cur_ciphertext[: pad_len]), bytes(cur_ciphertext[pad_len :]))
						assert isinstance(resp, bool)
						if not resp:
							continue
					candidate.append(x)
					if not faulty:
						break
				if not faulty and len(candidate) != 1:
					assert False, f"[ERROR] <forge_CBC_plaintext_with_padding_oracle> Failed to forge block {i}, index {j}: unique candidate expected"
				for x in candidate:
					q_next.append(plaintext[: pad_len * i + j] + [x] + plaintext[pad_len * i + j + 1 :])
			q = q_next
		for k in range(pad_len):
			ciphertext[pad_len * i + k] ^= pad_len
	res = [bytes(plaintext) for plaintext in q]
	return res[0] if not faulty else res

# padding_oracle_request(iv, ciphertext) checks whether the plaintext is padded, whose result can be read from padding_oracle_read()
# if faulty, padding_oracle returns True on some instances where it should return False
# Returns the plaintext if not faulty, otherwise all possible such plaintexts, such that CBC(plaintext, iv) = ciphertext
def forge_CBC_plaintext_with_batched_padding_oracle(iv: bytes, ciphertext : bytes, padding_oracle_request, padding_oracle_read, batch_size = 2**8, faulty = False, pool = list(range(2**8))):
	pool = list(sorted(set(map(int, pool))))
	assert 0 < len(pool) and 0 <= min(pool) and max(pool) < 2**8
	assert batch_size >= 1
	n, pad_len = len(ciphertext), 16
	assert pad_len > 0 and n % pad_len == 0 and n > 0
	ciphertext, plaintext = list(iv) + list(ciphertext), [0] * n
	q = [plaintext[:]]
	for i in reversed(range(n // pad_len)):
		for j in reversed(range(pad_len)):
			print(f"[INFO] <forge_CBC_plaintext_with_batched_padding_oracle> Forging block {i} at index {j}")
			for k in range(j, pad_len):
				ciphertext[pad_len * i + k] ^= pad_len - j ^ (pad_len - j - 1 if k > j else 0)
			q_next = []
			for plaintext in q:
				print(f"[INFO] <forge_CBC_plaintext_with_batched_padding_oracle> {plaintext = }")
				candidate = []
				for batch_start in range(0, len(pool), batch_size):
					for x in pool[batch_start : batch_start + batch_size]:
						plaintext[pad_len * i + j] = x
						cur_ciphertext = ciphertext[: pad_len * i] + list(x ^ y for x, y in zip(plaintext[pad_len * i : pad_len * (i + 1)], ciphertext[pad_len * i : pad_len * (i + 1)])) + ciphertext[pad_len * (i + 1) : pad_len * (i + 2)]
						padding_oracle_request(bytes(cur_ciphertext[: pad_len]), bytes(cur_ciphertext[pad_len :]))
						if j == pad_len - 1:
							ciphertext[pad_len * i + j - 1] ^= 1
							cur_ciphertext = ciphertext[: pad_len * i] + list(x ^ y for x, y in zip(plaintext[pad_len * i : pad_len * (i + 1)], ciphertext[pad_len * i : pad_len * (i + 1)])) + ciphertext[pad_len * (i + 1) : pad_len * (i + 2)]
							padding_oracle_request(bytes(cur_ciphertext[: pad_len]), bytes(cur_ciphertext[pad_len :]))
							ciphertext[pad_len * i + j - 1] ^= 1
					for x in pool[batch_start : batch_start + batch_size]:
						resps = [padding_oracle_read()]
						assert isinstance(resps[-1], bool)
						if j == pad_len - 1:
							resps.append(padding_oracle_read())
							assert isinstance(resps[-1], bool)
						if all(resps):
							candidate.append(x)
					if not faulty and len(candidate) > 0:
						break
				if not faulty and len(candidate) != 1:
					assert False, f"[ERROR] <forge_CBC_plaintext_with_batched_padding_oracle> Failed to forge block {i}, index {j}: unique candidate expected"
				for x in candidate:
					q_next.append(plaintext[: pad_len * i + j] + [x] + plaintext[pad_len * i + j + 1 :])
			q = q_next
		for k in range(pad_len):
			ciphertext[pad_len * i + k] ^= pad_len
	res = [bytes(plaintext) for plaintext in q]
	return res[0] if not faulty else res

if __name__ == "__main__":
	import random
	from Crypto.Cipher import AES
	from Crypto.Util.Padding import pad, unpad

	def test_forge_CBC_ciphertext_with_padding_oracle():
		key = pad(b"testkey", 16)
		plaintext = pad(b"Test_text_123234234!!{testing_zzzzzzzzz}_1232342245234234243", 16)
		hm = pad(b"hint_message", 16)
		hiv = pad(b"hint_iv", 16)
		hct = AES.new(key, AES.MODE_CBC, hiv).encrypt(hm)

		def padding_oracle(iv : bytes, ciphertext : bytes):
			cipher = AES.new(key, AES.MODE_CBC, iv)
			try:
				unpad(cipher.decrypt(ciphertext), 16)
				return True
			except Exception as e:
				return False

		iv, ciphertext = forge_CBC_ciphertext_with_padding_oracle(plaintext, padding_oracle)
		assert ciphertext == AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)
		iv, ciphertext = forge_CBC_ciphertext_with_padding_oracle(plaintext, padding_oracle, (hm, hiv, hct))
		assert ciphertext == AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)
		print("[test_forge_CBC_ciphertext_with_padding_oracle] OK")

	def test_forge_CBC_ciphertext_with_batched_padding_oracle():
		key = pad(b"testkey", 16)
		plaintext = pad(b"Test_text_123234234!!{testing_zzzzzzzzz}_1232342245234234243", 16)
		hm = pad(b"hint_message", 16)
		hiv = pad(b"hint_iv", 16)
		hct = AES.new(key, AES.MODE_CBC, hiv).encrypt(hm)

		res = []
		def padding_oracle_request(iv : bytes, ciphertext : bytes):
			cipher = AES.new(key, AES.MODE_CBC, iv)
			try:
				unpad(cipher.decrypt(ciphertext), 16)
				res.append(True)
			except Exception as e:
				res.append(False)
		def padding_oracle_read():
			nonlocal res
			resp, res = res[0], res[1:]
			return resp

		iv, ciphertext = forge_CBC_ciphertext_with_batched_padding_oracle(plaintext, padding_oracle_request, padding_oracle_read, batch_size = 79)
		assert ciphertext == AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)
		iv, ciphertext = forge_CBC_ciphertext_with_batched_padding_oracle(plaintext, padding_oracle_request, padding_oracle_read, batch_size = 79, hint = (hm, hiv, hct))
		assert ciphertext == AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)
		print("[test_forge_CBC_ciphertext_with_batched_padding_oracle] OK")

	def test_forge_CBC_plaintext_with_padding_oracle():
		key = pad(b"testkey", 16)
		iv = pad(b"testiv", 16)
		plaintext = pad(b"Test_text_123234234!!{testing_zzzzzzzzz}_1232342245234234243", 16)
		ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)

		def padding_oracle(iv : bytes, ciphertext : bytes):
			cipher = AES.new(key, AES.MODE_CBC, iv)
			try:
				unpad(cipher.decrypt(ciphertext), 16)
				return True
			except Exception as e:
				return False

		assert forge_CBC_plaintext_with_padding_oracle(iv, ciphertext, padding_oracle) == plaintext
		print("[test_forge_CBC_plaintext_with_padding_oracle] OK")

	def test_forge_CBC_plaintext_with_batched_padding_oracle():
		key = pad(b"testkey", 16)
		iv = pad(b"testiv", 16)
		plaintext = pad(b"Test_text_123234234!!{testing_zzzzzzzzz}_1232342245234234243", 16)
		ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)

		res = []
		def padding_oracle_request(iv : bytes, ciphertext : bytes):
			cipher = AES.new(key, AES.MODE_CBC, iv)
			try:
				unpad(cipher.decrypt(ciphertext), 16)
				res.append(True)
			except Exception as e:
				res.append(False)
		def padding_oracle_read():
			nonlocal res
			resp, res = res[0], res[1:]
			return resp

		assert forge_CBC_plaintext_with_batched_padding_oracle(iv, ciphertext, padding_oracle_request, padding_oracle_read, batch_size = 79) == plaintext
		print("[test_forge_CBC_plaintext_with_batched_padding_oracle] OK")

	test_forge_CBC_ciphertext_with_padding_oracle()
	test_forge_CBC_ciphertext_with_batched_padding_oracle()
	test_forge_CBC_plaintext_with_padding_oracle()
	test_forge_CBC_plaintext_with_batched_padding_oracle()
