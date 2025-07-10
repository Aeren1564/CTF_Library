import pkgutil
import importlib
import os

__all__ = []

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
