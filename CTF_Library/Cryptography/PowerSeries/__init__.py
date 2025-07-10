import pkgutil
import importlib
import os
import sys

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
