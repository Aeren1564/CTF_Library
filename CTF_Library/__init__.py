import pkgutil
import importlib
import os
import sys
sys.setrecursionlimit(10**9)

__version__ = "0.2.5"

__all__ = []

from Crypto.Cipher import AES, DES
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse, ceil_div, size, isPrime, getPrime, getStrongPrime, getRandomInteger, getRandomNBitInteger, getRandomRange
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
import hashlib
from base64 import b64encode, b64decode

from gmpy2 import is_square, isqrt, iroot
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import multiprocessing
import ast
import copy
import code
from fractions import Fraction
import string
import numpy
import itertools
import random
import secrets
import requests
import re
import traceback
import mpmath
import os
import json
import zlib
import subprocess
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from collections import defaultdict

import cuso

flag_char_set = "_{}:" + string.ascii_letters + string.digits + string.punctuation

__all__ += [
	# from Crypto.Cipher
	"AES",
	"DES",

	# from Crypto.Util.number
	"bytes_to_long",
	"long_to_bytes",
	"inverse",
	"ceil_div",
	"size",
	"isPrime",
	"getPrime",
	"getStrongPrime",
	"getRandomInteger",
	"getRandomNBitInteger",
	"getRandomRange",

	# from Crypto.Util.Padding
	"pad",
	"unpad",

	# from Crypto.Util.strxor
	"strxor",

	# from base64
	"b64encode",
	"b64decode",

	# from gmpy2
	"is_square",
	"isqrt",
	"iroot",

	# from multiprocessing and concurrent.futures
	"multiprocessing",
	"ProcessPoolExecutor",
	"ThreadPoolExecutor",
	"as_completed",

	# from collections
	"defaultdict",

	# modules imported directly, so include as module names:
	"hashlib",
	"ast",
	"copy",
	"Fraction",
	"code",
	"string",
	"numpy",
	"itertools",
	"random",
	"secrets",
	"requests",
	"re",
	"traceback",
	"mpmath",
	"os",
	"json",
	"zlib",
	"subprocess",
	"time",
	"urllib3",

	# cuso
	"cuso",

	# custom variable
	"flag_char_set",
]

import pwn
for name in dir(pwn):
	if not name.startswith("_"):
		try:
			globals()[name] = getattr(pwn, name)
			__all__.append(name)
		except AttributeError:
			# skip attributes that cannot be accessed
			pass

import sage.all
sage.all.proof.all(False)
for name in dir(sage.all):
	if not name.startswith("_"):
		try:
			globals()[name] = getattr(pwn, name)
			__all__.append(name)
		except AttributeError:
			# skip attributes that cannot be accessed
			pass

package_path = __path__[0]
package_name = __name__

# Import all Python modules and subpackages in this directory
for finder, name, is_pkg in pkgutil.iter_modules([package_path]):
	full_name = f"{package_name}.{name}"
	module = importlib.import_module(full_name)
	if hasattr(module, "__all__"):
		for symbol in module.__all__:
			globals()[symbol] = getattr(module, symbol)
		__all__.extend(module.__all__)
	else:
		for symbol in dir(module):
			if not symbol.startswith("_"):
				globals()[symbol] = getattr(module, symbol)
				__all__.append(symbol)
	if is_pkg:
		sub_path = module.__path__
		for sub_finder, sub_name, sub_ispkg in pkgutil.iter_modules(sub_path):
			sub_full_name = f"{full_name}.{sub_name}"
			sub_module = importlib.import_module(sub_full_name)
			if hasattr(sub_module, "__all__"):
				for symbol in sub_module.__all__:
					globals()[symbol] = getattr(sub_module, symbol)
				__all__.extend(sub_module.__all__)
			else:
				for symbol in dir(sub_module):
					if not symbol.startswith("_"):
						globals()[symbol] = getattr(sub_module, symbol)
						__all__.append(symbol)
