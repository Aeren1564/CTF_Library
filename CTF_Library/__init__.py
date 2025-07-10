import pkgutil
import importlib
import os
import sys

__version__ = "0.2.0"

__all__ = []

package_path = __path__[0]
package_name = __name__

# Import all .py modules and subpackages
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
# Import pybind11 extension modules (.so / .pyd)
for filename in os.listdir(package_path):
	if filename.endswith((".so", ".pyd")) and not filename.startswith("_"):
		modname = os.path.splitext(filename)[0]
		full_name = f"{package_name}.{modname}"
		if modname not in sys.modules:
			spec = importlib.util.find_spec(full_name)
			if spec is not None:
				module = importlib.util.module_from_spec(spec)
				spec.loader.exec_module(module)
				sys.modules[full_name] = module
			else:
				continue
		else:
			module = sys.modules[full_name]
		# Export all public symbols
		if hasattr(module, "__all__"):
			for symbol in module.__all__:
				globals()[symbol] = getattr(module, symbol)
			__all__.extend(module.__all__)
		else:
			for symbol in dir(module):
				if not symbol.startswith("_"):
					globals()[symbol] = getattr(module, symbol)
					__all__.append(symbol)

from sage.rings.factorint import factor_trial_division
from Crypto.Cipher import AES, DES
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse, ceil_div, size, isPrime, getPrime, getStrongPrime, getRandomInteger, getRandomNBitInteger, getRandomRange
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
import hashlib
from base64 import b64encode, b64decode

from multiprocessing import Pool
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from gmpy2 import isqrt, iroot
import ast
import copy
from fractions import Fraction
import string
import numpy
import itertools
import random
import secrets
import requests
import re
import traceback
import os
import json
import zlib
import subprocess
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from collections import defaultdict

flag_char_set = "_{}:" + string.ascii_letters + string.digits + string.punctuation

__all__ += [
	# from sage.rings.factorint
	"factor_trial_division",

	# from Crypto.Cipher
	"AES",
	"DES",

	# from Crypto.Hash
	"SHA256",

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

	# from multiprocessing and concurrent.futures
	"Pool",
	"ProcessPoolExecutor",
	"ThreadPoolExecutor",
	"as_completed",

	# from gmpy2
	"isqrt",
	"iroot",

	# from collections
	"defaultdict",

	# modules imported directly, so include as module names:
	"hashlib",
	"ast",
	"copy",
	"Fraction",
	"string",
	"numpy",
	"itertools",
	"random",
	"secrets",
	"requests",
	"re",
	"traceback",
	"os",
	"json",
	"zlib",
	"subprocess",
	"time",
	"urllib3",

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
