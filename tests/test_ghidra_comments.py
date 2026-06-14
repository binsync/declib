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
        "declib.decompilers.ghidra.compat.headless",
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


class FakeAddress:
    def __init__(self, offset):
        self._offset = offset

    def getOffset(self):
        return self._offset


class FakeFunction:
    def __init__(self, entry, body):
        self._entry = entry
        self._body = body

    def getEntryPoint(self):
        return FakeAddress(self._entry)

    def getBody(self):
        return self._body


class FakeCodeUnitInstance:
    def __init__(self, addr, comments):
        self._addr = addr
        self._comments = comments

    def getAddress(self):
        return FakeAddress(self._addr)

    def getComment(self, comment_type):
        return self._comments.get(comment_type)


class FakeListing:
    def __init__(self, code_units_by_body):
        self._code_units_by_body = code_units_by_body

    def getCodeUnits(self, body, forward):
        return iter(self._code_units_by_body[body])


class FakeFunctionManager:
    def __init__(self, funcs):
        self._funcs = funcs

    def getFunctions(self, forward):
        return iter(self._funcs)


class FakeProgram:
    def __init__(self, funcs, listing):
        self._func_manager = FakeFunctionManager(funcs)
        self._listing = listing

    def getFunctionManager(self):
        return self._func_manager

    def getListing(self):
        return self._listing


class TestGhidraComments(unittest.TestCase):
    def _make_interface(self, code_units):
        saved_modules = _install_ghidra_import_stubs()
        self.addCleanup(_restore_modules, saved_modules)
        from declib.decompilers.ghidra.interface import GhidraDecompilerInterface

        class TestableGhidraDecompilerInterface(GhidraDecompilerInterface):
            @property
            def currentProgram(self):
                return self._program_for_test

        func = FakeFunction(0x401000, "main_body")
        deci = object.__new__(TestableGhidraDecompilerInterface)
        deci._program_for_test = FakeProgram(
            [func],
            FakeListing({"main_body": code_units}),
        )
        return deci

    def test_comments_maps_ghidra_slots_to_portable_comment_kinds(self):
        deci = self._make_interface([
            FakeCodeUnitInstance(
                0x401000,
                {
                    FakeCodeUnit.PLATE_COMMENT: "plate",
                    FakeCodeUnit.EOL_COMMENT: "eol",
                    FakeCodeUnit.POST_COMMENT: "post",
                    FakeCodeUnit.REPEATABLE_COMMENT: "repeatable",
                },
            ),
            FakeCodeUnitInstance(0x401010, {FakeCodeUnit.PRE_COMMENT: "pre"}),
            FakeCodeUnitInstance(
                0x401020,
                {
                    FakeCodeUnit.PRE_COMMENT: "pre",
                    FakeCodeUnit.EOL_COMMENT: "eol",
                },
            ),
        ])

        comments = deci._comments()

        disassembly_comment = comments[0x401000]
        self.assertIsNone(disassembly_comment.func_addr)
        self.assertFalse(disassembly_comment.decompiled)
        self.assertEqual(
            disassembly_comment.comment,
            "[PLATE] plate\n[EOL] eol\n[POST] post\n[REPEATABLE] repeatable",
        )

        pseudocode_comment = comments[0x401010]
        self.assertIsNone(pseudocode_comment.func_addr)
        self.assertTrue(pseudocode_comment.decompiled)
        self.assertEqual(pseudocode_comment.comment, "pre")

        mixed_comment = comments[0x401020]
        self.assertIsNone(mixed_comment.func_addr)
        self.assertFalse(mixed_comment.decompiled)
        self.assertEqual(mixed_comment.comment, "[PRE] pre\n[EOL] eol")


if __name__ == "__main__":
    unittest.main()
