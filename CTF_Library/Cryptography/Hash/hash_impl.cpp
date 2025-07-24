#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <bits/stdc++.h>

namespace py = pybind11;

template<class Hash, bool is_little_endian, class word_type, size_t state_cnt, size_t block_size>
struct length_extendable_hash{
	static constexpr size_t bits_per_word = 8 * sizeof(word_type);
	static constexpr size_t bytes_per_word = sizeof(word_type);
	static_assert(block_size % bytes_per_word == 0);
	// # of bytes in the secret prefix
	size_t secret_len = 0;
	// plaintext following the secret prefix
	// secret_len + pt_cur.size() must be divisible by block_size
	std::string pt_cur;
	// plaintext following the pt_cur
	std::string pt_ext;
	std::array<word_type, state_cnt> state;
	length_extendable_hash(const std::array<word_type, state_cnt> &state): state(state){ }
	length_extendable_hash(size_t secret_len, py::bytes py_pt_cur, py::bytes py_digest_init): secret_len(secret_len), pt_cur(py_pt_cur){
		pad(pt_cur, size());
		string_to_array(std::string(py_digest_init), state, state_cnt);
	}
	static word_type rotl(word_type x, size_t shift){
		return x << shift | x >> (bits_per_word - shift);
	}
	static word_type rotr(word_type x, size_t shift){
		return x >> shift | x << (bits_per_word - shift);
	}
	static void string_to_array(const std::string &s, auto &arr, size_t cnt){
		arr.fill(0);
		if constexpr(is_little_endian)
			for(size_t i = 0; i < bytes_per_word * cnt; ++ i)
				arr[i / bytes_per_word] |= (word_type)(unsigned char)s[i] << i % bytes_per_word * 8;
		else
			for(size_t i = 0; i < bytes_per_word * cnt; ++ i)
				arr[i / bytes_per_word] |= (word_type)(unsigned char)s[i] << (bytes_per_word - 1 - i % bytes_per_word) * 8;
	}
	static void pad(std::string &pt, size_t original_len){
		pt.push_back(0x80);
		for(size_t len = original_len + 1; len % block_size != block_size - 2 * bytes_per_word; ++ len) pt.push_back(0x00);
		original_len *= 8;
		pt.resize(pt.size() + 2 * bytes_per_word);
		if constexpr(is_little_endian)
			for(size_t i = 0; i < 2 * bytes_per_word; ++ i){
				pt[pt.size() - 2 * bytes_per_word + i] = original_len % 256;
				original_len >>= 8;
			}
		else
			for(size_t i = 0; i < 2 * bytes_per_word; ++ i){
				pt[pt.size() - 1 - i] = original_len % 256;
				original_len >>= 8;
			}
	}
	size_t size() const{
		return secret_len + pt_cur.size() + pt_ext.size();
	}
	py::bytes get_plaintext() const{
		return py::bytes(pt_cur + pt_ext);
	}
	void flush(){
		if(pt_ext.size() < block_size) return;
		for(size_t i = 0; i + block_size <= pt_ext.size(); i += block_size) Hash::compress(pt_ext.substr(i, block_size), state);
		pt_cur += pt_ext.substr(0, pt_ext.size() / block_size * block_size);
		pt_ext = pt_ext.substr(pt_ext.size() / block_size * block_size);
	}
	void complete(){
		pad(pt_ext, size());
		flush();
	}
	void extend(py::bytes py_pt){
		pt_ext += std::string(py_pt);
		flush();
	}
	py::bytes digest(){
		std::string pt = pt_ext;
		pad(pt, size());
		auto res = state;
		for(size_t i = 0; i < pt.size(); i += block_size) Hash::compress(pt.substr(i, block_size), res);
		std::string output(bytes_per_word * state_cnt, 0);
		if constexpr(is_little_endian)
			for(size_t i = 0; i < bytes_per_word * state_cnt; ++ i)
				output[i] = res[i / bytes_per_word] >> i % bytes_per_word * 8 & 255;
		else
			for(size_t i = 0; i < bytes_per_word * state_cnt; ++ i)
				output[i] = res[i / bytes_per_word] >> (bytes_per_word - 1 - i % bytes_per_word) * 8 & 255;
		return py::bytes(output);
	}
};

// Source: https://en.wikipedia.org/wiki/MD5#Pseudocode
struct MD5_impl: length_extendable_hash<MD5_impl, true, uint32_t, 4, 64>{
	// Shift amounts on each round
	static constexpr std::array<uint32_t, 64> s = {
		7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
		5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
		4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
		6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
	};
	// k[i] = floor(2^32 * abs(sin(i + 1)))
	static constexpr std::array<uint32_t, 64> k = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
	};
	MD5_impl():
		length_extendable_hash({
			0x67452301,
			0xefcdab89,
			0x98badcfe,
			0x10325476,
		}){ }
	MD5_impl(size_t secret_len, py::bytes py_pt_cur, py::bytes py_digest_init): length_extendable_hash(secret_len, py_pt_cur, py_digest_init){ }
	static void compress(const std::string &chunk, std::array<uint32_t, 4> &state){
		static std::array<uint32_t, 16> w;
		string_to_array(chunk, w, 16);
		uint32_t A = state[0];
		uint32_t B = state[1];
		uint32_t C = state[2];
		uint32_t D = state[3];
		for(auto i = 0; i < 64; ++ i){
			uint32_t F, g;
			if(i < 16){
				F = (B & C) | (~B & D);
				g = i;
			}
			else if(i < 32){
				F = (D & B) | (~D & C);
				g = (5 * i + 1) % 16;
			}
			else if(i < 48){
				F = B ^ C ^ D;
				g = (3 * i + 5) % 16;
			}
			else{
				F = C ^ (B | ~D);
				g = 7 * i % 16;
			}
			F += A + k[i] + w[g];
			A = D;
			D = C;
			C = B;
			B += rotl(F, s[i]);
		}
		state[0] += A;
		state[1] += B;
		state[2] += C;
		state[3] += D;
	}
};

// Source: https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
struct SHA1_impl: length_extendable_hash<SHA1_impl, false, uint32_t, 5, 64>{
	SHA1_impl():
		length_extendable_hash({
			0x67452301,
			0xEFCDAB89,
			0x98BADCFE,
			0x10325476,
			0xC3D2E1F0,
		}){ }
	SHA1_impl(size_t secret_len, py::bytes py_pt_cur, py::bytes py_digest_init): length_extendable_hash(secret_len, py_pt_cur, py_digest_init){ }
	static void compress(const std::string &chunk, std::array<uint32_t, 5> &state){
		static std::array<uint32_t, 80> w;
		string_to_array(chunk, w, 16);
		for(auto i = 16; i < 80; ++ i)
			w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
		uint32_t a = state[0];
		uint32_t b = state[1];
		uint32_t c = state[2];
		uint32_t d = state[3];
		uint32_t e = state[4];
		for(auto i = 0; i < 80; ++ i){
			uint32_t f, k;
			if(i < 20){
				f = (b & c) | (~b & d);
				k = 0x5A827999;
			}
			else if(i < 40){
				f = b ^ c ^ d;
				k = 0x6ED9EBA1;
			}
			else if(i < 60){
				f = (b & c) ^ (b & d) ^ (c & d);
				k = 0x8F1BBCDC;
			}
			else{
				f = b ^ c ^ d;
				k = 0xCA62C1D6;
			}
			uint32_t temp = rotl(a, 5) + f + e + k + w[i];
			e = d;
			d = c;
			c = rotl(b, 30);
			b = a;
			a = temp;
		}
		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;
		state[4] += e;
	}
};

// Source: https://en.wikipedia.org/wiki/SHA-2#Pseudocode
struct SHA256_impl: length_extendable_hash<SHA256_impl, false, uint32_t, 8, 64>{
	// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311
	static constexpr std::array<uint32_t, 64> k = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};
	// first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19
	SHA256_impl():
		length_extendable_hash({
			0x6a09e667,
			0xbb67ae85,
			0x3c6ef372,
			0xa54ff53a,
			0x510e527f,
			0x9b05688c,
			0x1f83d9ab,
			0x5be0cd19,
		}){ }
	SHA256_impl(size_t secret_len, py::bytes py_pt_cur, py::bytes py_digest_init): length_extendable_hash(secret_len, py_pt_cur, py_digest_init){ }
	static void compress(const std::string &chunk, std::array<uint32_t, 8> &state){
		static std::array<uint32_t, 64> w;
		string_to_array(chunk, w, 16);
		for(auto i = 16; i < 64; ++ i){
			uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
			uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}
		uint32_t a = state[0];
		uint32_t b = state[1];
		uint32_t c = state[2];
		uint32_t d = state[3];
		uint32_t e = state[4];
		uint32_t f = state[5];
		uint32_t g = state[6];
		uint32_t h = state[7];
		for(auto i = 0; i < 64; ++ i){
			uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
			uint32_t ch = (e & f) ^ (~e & g);
			uint32_t temp1 = h + S1 + ch + k[i] + w[i];
			uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
			uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
			uint32_t temp2 = S0 + maj;
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}
		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;
		state[4] += e;
		state[5] += f;
		state[6] += g;
		state[7] += h;
	}
};

// Source: https://en.wikipedia.org/wiki/SHA-2#Pseudocode
struct SHA512_impl: length_extendable_hash<SHA512_impl, false, uint64_t, 8, 128>{
	// first 64 bits of the fractional parts of the cube roots of the first 80 primes 2..409
	static constexpr std::array<uint64_t, 80> k = {
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
		0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
		0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
		0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
		0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
		0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
		0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
		0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
		0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
		0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
		0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
		0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
		0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
	};
	// first 64 bits of the fractional parts of the square roots of the first 8 primes 2..19
	SHA512_impl():
		length_extendable_hash({
			0x6a09e667f3bcc908,
			0xbb67ae8584caa73b,
			0x3c6ef372fe94f82b,
			0xa54ff53a5f1d36f1,
			0x510e527fade682d1,
			0x9b05688c2b3e6c1f,
			0x1f83d9abfb41bd6b,
			0x5be0cd19137e2179
		}){ }
	SHA512_impl(size_t secret_len, py::bytes py_pt_cur, py::bytes py_digest_init): length_extendable_hash(secret_len, py_pt_cur, py_digest_init){ }
	static void compress(const std::string &chunk, std::array<uint64_t, 8> &state){
		static std::array<uint64_t, 80> w;
		string_to_array(chunk, w, 16);
		for(auto i = 16; i < 80; ++ i){
			uint64_t s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
			uint64_t s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}
		uint64_t a = state[0];
		uint64_t b = state[1];
		uint64_t c = state[2];
		uint64_t d = state[3];
		uint64_t e = state[4];
		uint64_t f = state[5];
		uint64_t g = state[6];
		uint64_t h = state[7];
		for(auto i = 0; i < 80; ++ i){
			uint64_t S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
			uint64_t ch = (e & f) ^ (~e & g);
			uint64_t temp1 = h + S1 + ch + k[i] + w[i];
			uint64_t S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
			uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
			uint64_t temp2 = S0 + maj;
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}
		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;
		state[4] += e;
		state[5] += f;
		state[6] += g;
		state[7] += h;
	}
};

PYBIND11_MODULE(hash_impl, m){
	py::class_<MD5_impl>(m, "MD5_impl")
		.def(py::init<>())
		.def(py::init<size_t, py::bytes, py::bytes>())
		.def("size", &MD5_impl::size)
		.def("get_plaintext", &MD5_impl::get_plaintext)
		.def("complete", &MD5_impl::complete)
		.def("extend", &MD5_impl::extend)
		.def("digest", &MD5_impl::digest);

	py::class_<SHA1_impl>(m, "SHA1_impl")
		.def(py::init<>())
		.def(py::init<size_t, py::bytes, py::bytes>())
		.def("size", &SHA1_impl::size)
		.def("get_plaintext", &SHA1_impl::get_plaintext)
		.def("complete", &SHA1_impl::complete)
		.def("extend", &SHA1_impl::extend)
		.def("digest", &SHA1_impl::digest);

	py::class_<SHA256_impl>(m, "SHA256_impl")
		.def(py::init<>())
		.def(py::init<size_t, py::bytes, py::bytes>())
		.def("size", &SHA256_impl::size)
		.def("get_plaintext", &SHA256_impl::get_plaintext)
		.def("complete", &SHA256_impl::complete)
		.def("extend", &SHA256_impl::extend)
		.def("digest", &SHA256_impl::digest);

	py::class_<SHA512_impl>(m, "SHA512_impl")
		.def(py::init<>())
		.def(py::init<size_t, py::bytes, py::bytes>())
		.def("size", &SHA512_impl::size)
		.def("get_plaintext", &SHA512_impl::get_plaintext)
		.def("complete", &SHA512_impl::complete)
		.def("extend", &SHA512_impl::extend)
		.def("digest", &SHA512_impl::digest);
}