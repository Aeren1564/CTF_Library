class MD5:
	# no argument: default constructor
	# 3 arguments: (secret_len, plaintext prefix, initial digest) - for length extension attack
	def __init__(self, *args):
		from CTF_Library.Cryptography.Hash.hash_impl import MD5_impl
		args = list(args)
		assert len(args) in [0, 3]
		if len(args) == 3:
			assert isinstance(args[0], int) and args[0] >= 0
			assert isinstance(args[1], bytes)
			assert isinstance(args[2], bytes) and len(args[2]) == 16
		self.impl = MD5_impl(*args)
	# size of underlying plaintext, possibly prepended by some secret text
	def size(self):
		return self.impl.size()
	def get_plaintext(self):
		return self.impl.get_plaintext()
	# pad plaintext as if digest() has been called
	def complete(self):
		self.impl.complete()
		return self
	def extend(self, plaintext: bytes):
		assert isinstance(plaintext, bytes)
		self.impl.extend(plaintext)
		return self
	def digest(self):
		return self.impl.digest()
	def hexdigest(self):
		return self.impl.digest().hex()

class SHA1:
	# no argument: default constructor
	# 3 arguments: (secret_len, plaintext prefix, initial digest) - for length extension attack
	def __init__(self, *args):
		from CTF_Library.Cryptography.Hash.hash_impl import SHA1_impl
		args = list(args)
		assert len(args) in [0, 3]
		if len(args) == 3:
			assert isinstance(args[0], int) and args[0] >= 0
			assert isinstance(args[1], bytes)
			assert isinstance(args[2], bytes) and len(args[2]) == 20
		self.impl = SHA1_impl(*args)
	# size of underlying plaintext, possibly prepended by some secret text
	def size(self):
		return self.impl.size()
	def get_plaintext(self):
		return self.impl.get_plaintext()
	# pad plaintext as if digest() has been called
	def complete(self):
		self.impl.complete()
		return self
	def extend(self, plaintext: bytes):
		assert isinstance(plaintext, bytes)
		self.impl.extend(plaintext)
		return self
	def digest(self):
		return self.impl.digest()
	def hexdigest(self):
		return self.impl.digest().hex()

class SHA256:
	# no argument: default constructor
	# 3 arguments: (secret_len, plaintext prefix, initial digest) - for length extension attack
	def __init__(self, *args):
		from CTF_Library.Cryptography.Hash.hash_impl import SHA256_impl
		args = list(args)
		assert len(args) in [0, 3]
		if len(args) == 3:
			assert isinstance(args[0], int) and args[0] >= 0
			assert isinstance(args[1], bytes)
			assert isinstance(args[2], bytes) and len(args[2]) == 32
		self.impl = SHA256_impl(*args)
	# size of underlying plaintext, possibly prepended by some secret text
	def size(self):
		return self.impl.size()
	def get_plaintext(self):
		return self.impl.get_plaintext()
	# pad plaintext as if digest() has been called
	def complete(self):
		self.impl.complete()
		return self
	def extend(self, plaintext: bytes):
		assert isinstance(plaintext, bytes)
		self.impl.extend(plaintext)
		return self
	def digest(self):
		return self.impl.digest()
	def hexdigest(self):
		return self.impl.digest().hex()

class SHA512:
	# no argument: default constructor
	# 3 arguments: (secret_len, plaintext prefix, initial digest) - for length extension attack
	def __init__(self, *args):
		from CTF_Library.Cryptography.Hash.hash_impl import SHA512_impl
		args = list(args)
		assert len(args) in [0, 3]
		if len(args) == 3:
			assert isinstance(args[0], int) and args[0] >= 0
			assert isinstance(args[1], bytes)
			assert isinstance(args[2], bytes) and len(args[2]) == 64
		self.impl = SHA512_impl(*args)
	# size of underlying plaintext, possibly prepended by some secret text
	def size(self):
		return self.impl.size()
	def get_plaintext(self):
		return self.impl.get_plaintext()
	# pad plaintext as if digest() has been called
	def complete(self):
		self.impl.complete()
		return self
	def extend(self, plaintext: bytes):
		assert isinstance(plaintext, bytes)
		self.impl.extend(plaintext)
		return self
	def digest(self):
		return self.impl.digest()
	def hexdigest(self):
		return self.impl.digest().hex()

if __name__ == "__main__":
	import hashlib
	import random

	def test_MD5():
		for text in [
			b"",
			b"The quick brown fox jumps over the lazy dog",
			random.randbytes(1000),
		]:
			res = MD5().extend(text).hexdigest()
			expected = hashlib.md5(text).hexdigest()
			assert res == expected
		print(f"[test_MD5] Ok")

	def test_MD5_length_extension_attack():
		for secret_len in list(range(100)) + list(range(1000, 1100)):
			secret = random.randbytes(secret_len)
			text0 = random.randbytes(54321)
			text1 = random.randbytes(54321)
			init_digest = hashlib.md5(secret + text0).digest()
			md = MD5(secret_len, text0, init_digest).extend(text1)
			res = md.hexdigest()
			expected = hashlib.md5(secret + md.get_plaintext()).hexdigest()
			assert res == expected
		print(f"[test_MD5_length_extension_attack] Ok")

	def test_SHA1():
		for text in [
			# b"",
			b"The quick brown fox jumps over the lazy dog",
			random.randbytes(1000),
		]:
			res = SHA1().extend(text).hexdigest()
			expected = hashlib.sha1(text).hexdigest()
			assert res == expected
		print(f"[test_SHA1] Ok")

	def test_SHA1_length_extension_attack():
		for secret_len in list(range(100)) + list(range(1000, 1100)):
			secret = random.randbytes(secret_len)
			text0 = random.randbytes(54321)
			text1 = random.randbytes(54321)
			init_digest = hashlib.sha1(secret + text0).digest()
			sha1 = SHA1(secret_len, text0, init_digest).extend(text1)
			res = sha1.hexdigest()
			expected = hashlib.sha1(secret + sha1.get_plaintext()).hexdigest()
			assert res == expected
		print(f"[test_SHA1_length_extension_attack] Ok")

	def test_SHA256():
		for text in [
			b"",
			b"The quick brown fox jumps over the lazy dog",
			random.randbytes(1000),
		]:
			res = SHA256().extend(text).hexdigest()
			expected = hashlib.sha256(text).hexdigest()
			assert res == expected
		print(f"[test_SHA256] Ok")

	def test_SHA256_length_extension_attack():
		for secret_len in list(range(100)) + list(range(1000, 1100)):
			secret = random.randbytes(secret_len)
			text0 = random.randbytes(54321)
			text1 = random.randbytes(54321)
			init_digest = hashlib.sha256(secret + text0).digest()
			sha256 = SHA256(secret_len, text0, init_digest).extend(text1)
			res = sha256.hexdigest()
			expected = hashlib.sha256(secret + sha256.get_plaintext()).hexdigest()
			assert res == expected
		print(f"[test_SHA256_length_extension_attack] Ok")

	def test_SHA512():
		for text in [
			b"",
			b"The quick brown fox jumps over the lazy dog",
			random.randbytes(1000),
		]:
			res = SHA512().extend(text).hexdigest()
			expected = hashlib.sha512(text).hexdigest()
			assert res == expected
		print(f"[test_SHA512] Ok")

	def test_SHA512_length_extension_attack():
		for secret_len in list(range(100)) + list(range(1000, 1100)):
			secret = random.randbytes(secret_len)
			text0 = random.randbytes(54321)
			text1 = random.randbytes(54321)
			init_digest = hashlib.sha512(secret + text0).digest()
			sha512 = SHA512(secret_len, text0, init_digest).extend(text1)
			res = sha512.hexdigest()
			expected = hashlib.sha512(secret + sha512.get_plaintext()).hexdigest()
			assert res == expected
		print(f"[test_SHA512_length_extension_attack] Ok")

	test_MD5()
	test_MD5_length_extension_attack()
	test_SHA1()
	test_SHA1_length_extension_attack()
	test_SHA256()
	test_SHA256_length_extension_attack()
	test_SHA512()
	test_SHA512_length_extension_attack()
