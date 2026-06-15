import sys
import types
import unittest


_MISSING = object()


class FakeCodeUnit:
    EOL_COMMENT = 0
    PRE_COMMENT = 1
    POST_COMMENT = 2
    PLATE_COMMENT = 3
    REPEATABLE_COMMENT = 4


def _restore_modules(saved_modules):
    for name, module in saved_modules.items():
        if module is _MISSING:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


def _install_ghidra_import_stubs():
    module_names = (
        "pyghidra",
        "pyghidra.core",
        "jpype",
        "declib.decompilers.ghidra.compat.imports",
        "declib.decompilers.ghidra.interface",
    )
    saved_modules = {name: sys.modules.get(name, _MISSING) for name in module_names}

    pyghidra_mod = types.ModuleType("pyghidra")
    pyghidra_core_mod = types.ModuleType("pyghidra.core")
    pyghidra_core_mod._analyze_program = lambda *args, **kwargs: None
    pyghidra_core_mod._get_language = lambda *args, **kwargs: None
    pyghidra_core_mod._get_compiler_spec = lambda *args, **kwargs: None
    sys.modules.setdefault("pyghidra", pyghidra_mod)
    sys.modules.setdefault("pyghidra.core", pyghidra_core_mod)

    jpype_mod = types.ModuleType("jpype")
    jpype_mod.JClass = type
    sys.modules.setdefault("jpype", jpype_mod)

    compat_imports_mod = types.ModuleType("declib.decompilers.ghidra.compat.imports")
    compat_imports_mod.CodeUnit = FakeCodeUnit
    sys.modules["declib.decompilers.ghidra.compat.imports"] = compat_imports_mod
    return saved_modules


class TestGhidraServerDispatch(unittest.TestCase):
    def test_gui_ghidra_requires_server_main_thread_dispatch(self):
        saved_modules = _install_ghidra_import_stubs()
        self.addCleanup(_restore_modules, saved_modules)
        from declib.decompilers.ghidra.interface import GhidraDecompilerInterface

        self.assertTrue(GhidraDecompilerInterface.requires_main_thread_dispatch)


if __name__ == "__main__":
    unittest.main()
