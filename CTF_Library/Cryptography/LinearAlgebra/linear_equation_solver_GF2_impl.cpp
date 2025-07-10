#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <bits/stdc++.h>
#include <memory>
#include <immintrin.h>
#define ALIGNED_ALLOC(size, alignment) _mm_malloc(size, alignment)
#define ALIGNED_FREE(ptr) _mm_free(ptr)

namespace py = pybind11;

template<class T, size_t Alignment>
struct AlignedAllocator{
	using value_type = T;
	using pointer = T *;
	using const_pointer = const T *;
	using reference = T &;
	using const_reference = const T &;
	using size_type = std::size_t;
	using difference_type = std::ptrdiff_t;
	AlignedAllocator() noexcept = default;
	template<class U> AlignedAllocator(const AlignedAllocator<U, Alignment>&) noexcept {}
	template<class U> struct rebind{ using other = AlignedAllocator<U, Alignment>; };
	pointer allocate(size_type n){
		if(n == 0) return nullptr;
		if(n > max_size()) throw std::length_error("AlignedAllocator::allocate() - Integer overflow.");
		void *ptr = ALIGNED_ALLOC(n * sizeof(T), Alignment);
		if(!ptr) throw std::bad_alloc();
		return static_cast<pointer>(ptr);
	}
	void deallocate(pointer p, size_type){ ALIGNED_FREE(p); }
	bool operator==(const AlignedAllocator&) const{ return true; }
	bool operator!=(const AlignedAllocator&) const{ return false; }
	size_type max_size() const noexcept {
		return static_cast<size_type>(-1) / sizeof(T);
	}
};

typedef uint64_t v8int64 __attribute__((vector_size(64), aligned(64)));
using aligned_vector = std::vector<uint64_t, AlignedAllocator<uint64_t, 64>>;

aligned_vector pyint_to_aligned_array(py::int_ pyx, int nb){
	assert(!pyx.is_none());
	PyObject* py_long = pyx.ptr();
	aligned_vector result(nb);
	int status = _PyLong_AsByteArray(
		(PyLongObject *)py_long,
		reinterpret_cast<unsigned char*>(result.data()),
		nb * sizeof(uint64_t),
		1, // little-endian
		0  // is_signed
	);
	if(status == -1) throw py::error_already_set();
	return result;
}

py::int_ array_to_pyint(const aligned_vector &x){
	PyObject* py_long = _PyLong_FromByteArray(
		reinterpret_cast<const unsigned char *>(x.data()),
		x.size() * sizeof(uint64_t),
		1, // little-endian
		0  // is_signed
	);
	if(!py_long) throw py::error_already_set();
	return py::reinterpret_steal<py::int_>(py_long);
}

void vectorized_xor(aligned_vector &x, const aligned_vector &y){
	assert((int)x.size() == (int)y.size());
	int nb = (int)x.size();
	for(auto i = 0; i < nb; i += 8){
		if(i + 8 <= nb){
			v8int64 *vec_x_ptr = reinterpret_cast<v8int64*>(&x[i]);
			v8int64 vec_y = *reinterpret_cast<const v8int64*>(&y[i]);
			*vec_x_ptr ^= vec_y;
		}
		else for(auto j = 0; i + j < nb; ++ j) x[i + j] ^= y[i + j];
	}
}

struct linear_equation_solver_GF2_impl{
	static constexpr int w = sizeof(uint64_t) * 8;
	int n, nb;
	std::vector<aligned_vector> equations;
	std::vector<int> pivots;
	std::vector<int> outputs;
	linear_equation_solver_GF2_impl(int n): n(n), nb((n + w - 1) / w){}
	int rank() const {
		return (int)equations.size();
	}
	int nullity() const {
		return n - rank();
	}
	auto reduce(py::int_ py_equation, int py_output){
		auto equation = pyint_to_aligned_array(py_equation, nb);
		int output = py_output;
		for(const auto &[basis_equation, basis_pivot, basis_output]: std::views::zip(equations, pivots, outputs)){
			if(equation[basis_pivot / w] >> basis_pivot % w & 1){
				vectorized_xor(equation, basis_equation);
				output ^= basis_output;
			}
		}
		return std::pair{equation, output};
	}
	bool add_equation_if_consistent(py::int_ py_equation, int py_output){
		auto [equation, output] = reduce(py_equation, py_output);
		if(std::ranges::all_of(equation, [&](auto x){ return x == 0; })) return output == 0;
		int pivot = -1;
		for(auto i = 0; i < nb; ++ i) if(equation[i]){
			for(auto j = 0; j < w; ++ j) if(equation[i] >> j & 1){
				pivot = w * i + j;
				break;
			}
			break;
		}
		for(auto i = 0; i < rank(); ++ i) if(equations[i][pivot / w] >> pivot % w & 1){
			vectorized_xor(equations[i], equation);
			outputs[i] ^= output;
		}
		equations.push_back(equation);
		pivots.push_back(pivot);
		outputs.push_back(output);
		return true;
	}
	auto solve() const{
		aligned_vector assignment(nb);
		std::vector<py::int_> basis;
		std::vector<int> is_pivot(n);
		for(auto pivot: pivots) is_pivot[pivot] = true;
		for(auto i = 0; i < rank(); ++ i) if(outputs[i]) assignment[pivots[i] / w] |= uint64_t{1} << pivots[i] % w;
		for(auto i = 0; i < n; ++ i) if(!is_pivot[i]){
			aligned_vector b(nb);
			b[i / w] |= uint64_t{1} << i % w;
			for(auto j = 0; j < rank(); ++ j) if(equations[j][i / w] >> i % w & 1) b[pivots[j] / w] |= uint64_t{1} << pivots[j] % w;
			basis.push_back(array_to_pyint(b));
		}
		return std::pair{array_to_pyint(assignment), basis};
	}
};

PYBIND11_MODULE(linear_equation_solver_GF2_impl, m) {
	py::class_<linear_equation_solver_GF2_impl>(m, "linear_equation_solver_GF2_impl")
		.def(py::init<int>())
		.def("add_equation_if_consistent", &linear_equation_solver_GF2_impl::add_equation_if_consistent)
		.def("rank", &linear_equation_solver_GF2_impl::rank)
		.def("nullity", &linear_equation_solver_GF2_impl::nullity)
		.def("solve", &linear_equation_solver_GF2_impl::solve);
}