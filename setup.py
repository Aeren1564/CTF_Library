from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
import pybind11

ext_modules = [
	Extension(
		name = "CTF_Library.Cryptography.LinearAlgebra.linear_equation_solver_GF2_impl",
		sources = ["CTF_Library/Cryptography/LinearAlgebra/linear_equation_solver_GF2_impl.cpp"],
		include_dirs = [
			pybind11.get_include(),
			"CTF_Library",
		],
		extra_compile_args = ["-std=c++26", "-O3", "-march=native"],
		language = "c++",
	),
	Extension(
		name = "CTF_Library.Cryptography.Hash.hash_impl",
		sources = ["CTF_Library/Cryptography/Hash/hash_impl.cpp"],
		include_dirs = [
			pybind11.get_include(),
			"CTF_Library",
		],
		extra_compile_args = ["-std=c++26", "-O3", "-march=native"],
		language = "c++",
	),
	Extension(
		name = "CTF_Library.Cryptography.EllipticCurve.ECDLP_bounded_impl",
		sources = ["CTF_Library/Cryptography/EllipticCurve/ECDLP_bounded_impl.cpp"],
		include_dirs = [
			pybind11.get_include(),
			"CTF_Library",
		],
		extra_compile_args = ["-std=c++26", "-O3", "-march=native"],
		libraries = ["gmpxx", "gmp"],
		language = "c++",
	),
]

setup(
	ext_modules=ext_modules,
)
