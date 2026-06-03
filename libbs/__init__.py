"""
The 'libbs' package has been renamed to 'declib'.

This module is a thin backwards-compatibility shim that:
- emits a DeprecationWarning on import,
- forwards `libbs.X` imports to `declib.X` so existing code keeps working,
- will not receive further updates.

Please install `declib` and update your imports:

    pip install declib
    import declib  # was: import libbs
"""
import importlib
import sys
import warnings
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import ModuleSpec

__version__ = "3.8.1"

warnings.warn(
    "'libbs' has been renamed to 'declib'. Install 'declib' (pip install declib) "
    "and replace 'libbs' with 'declib' in your imports. This shim forwards to "
    "'declib' but will be removed in a future release.",
    DeprecationWarning,
    stacklevel=2,
)


class _DecLibAliasLoader(Loader):
    def create_module(self, spec):
        target = "declib" + spec.name[len("libbs"):]
        module = importlib.import_module(target)
        sys.modules[spec.name] = module
        return module

    def exec_module(self, module):
        return None


class _DecLibAliasFinder(MetaPathFinder):
    """Resolve `libbs.X` imports to the matching `declib.X` module."""

    _loader = _DecLibAliasLoader()

    def find_spec(self, fullname, path=None, target=None):
        if fullname != "libbs" and not fullname.startswith("libbs."):
            return None
        return ModuleSpec(fullname, self._loader, is_package=True)


sys.meta_path.insert(0, _DecLibAliasFinder())

# Mirror declib's top-level attributes onto libbs so `libbs.foo` works without
# routing through the finder.
import declib as _declib  # noqa: E402

for _attr in dir(_declib):
    if not _attr.startswith("_"):
        globals()[_attr] = getattr(_declib, _attr)

del _declib, _attr
