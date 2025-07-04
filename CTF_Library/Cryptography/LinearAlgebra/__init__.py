import pkgutil
import importlib
import os
import sys

__all__ = []

# Get the current package's path and name
package_path = __path__[0]
package_name = __name__

# Auto-import all submodules/packages and top-level .py files
for finder, name, is_pkg in pkgutil.iter_modules([package_path]):
	full_name = f"{package_name}.{name}"
	module = importlib.import_module(full_name)
	# Import everything from __all__ if defined
	if hasattr(module, "__all__"):
		for symbol in module.__all__:
			globals()[symbol] = getattr(module, symbol)
		__all__.extend(module.__all__)
	else:
		# Fallback: import all public symbols not starting with _
		for symbol in dir(module):
			if not symbol.startswith("_"):
				globals()[symbol] = getattr(module, symbol)
				__all__.append(symbol)
