"""
Tests for the `decompiler` CLI and the new declib core features it exposes
(list_strings, get_callers, disassemble, xref_to_addr, xref_from).

The CLI tests are backend-parametrized: each test method lives on a single
base class, and one subclass per supported decompiler re-runs them with a
different ``backend`` class attribute. Backends whose dependencies aren't
available are skipped.

Subprocesses are used on purpose so the real entry point + server-registry
flow is exercised end-to-end.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from declib.api import server_registry
from declib.api.decompiler_client import DecompilerClient
from declib.api.decompiler_interface import DecompilerInterface


TEST_BINARIES_DIR = Path(
    os.getenv("TEST_BINARIES_DIR", Path(__file__).parent.parent.parent / "bs-artifacts" / "binaries")
)
FAUXWARE_PATH = TEST_BINARIES_DIR / "fauxware"
POSIX_SYSCALL_PATH = TEST_BINARIES_DIR / "posix_syscall"


# ---------------------------------------------------------------------------
# Backend availability detection: skip subclasses cleanly when a decompiler
# isn't installed. Keep these tight and cheap — don't actually load a binary.
# ---------------------------------------------------------------------------

def _backend_available(backend: str) -> bool:
    try:
        if backend == "angr":
            import angr  # noqa: F401
        elif backend == "ghidra":
            import pyghidra  # noqa: F401
            if not os.environ.get("GHIDRA_INSTALL_DIR"):
                return False
        elif backend == "binja":
            import binaryninja  # noqa: F401
        elif backend == "ida":
            import idapro  # noqa: F401
        else:
            return False
    except Exception:
        return False
    return True


def _cli_env():
    env = os.environ.copy()
    # Isolate registry per-test so concurrent test runs don't collide and stale
    # servers from previous runs don't leak in.
    env["DECLIB_SERVER_REGISTRY"] = _REGISTRY_DIR
    return env


def _run_cli(*args, check=True, timeout=600, env_overrides=None) -> subprocess.CompletedProcess:
    """Run the `decompiler` CLI and return the result."""
    cmd = [sys.executable, "-m", "declib.cli.decompiler_cli", *args]
    env = _cli_env()
    for key, value in (env_overrides or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout, env=env)


def _format_hex(value: int) -> str:
    """Tiny helper: render an int as ``0x...`` for CLI args."""
    return f"0x{value:x}"


# Shared registry directory for this module's tests
_REGISTRY_DIR = tempfile.mkdtemp(prefix="declib_cli_registry_")


def _stop_all_servers():
    """Best-effort teardown: kill every server present in the registry."""
    os.environ["DECLIB_SERVER_REGISTRY"] = _REGISTRY_DIR
    try:
        records = server_registry.list_servers(prune_stale=False)
    except Exception:
        records = []
    for record in records:
        try:
            client = DecompilerClient(socket_path=record["socket_path"])
            try:
                client._send_request({"type": "shutdown_deci"})
            except Exception:
                pass
            client.shutdown()
        except Exception:
            pass
        finally:
            server_registry.unregister_server(record.get("id"))
            # Also try to SIGKILL the PID as a fallback
            pid = record.get("pid")
            if pid:
                try:
                    os.kill(int(pid), 9)
                except Exception:
                    pass


class _CLIBackendTestBase(unittest.TestCase):
    """Base class for backend-parametrized CLI tests.

    Subclasses set ``backend`` to one of ``angr``, ``ghidra``, ``binja``,
    ``ida``. Tests that rely on angr-specific quirks are gated inside the
    method body rather than being split into separate subclasses, so a
    single test method describes "what the CLI should do against any
    backend" and the backend-specific allowances live near the asserts.
    """

    backend: str = "angr"

    @classmethod
    def setUpClass(cls):
        # `_CLIBackendTestBase` itself is abstract; skip it so unittest doesn't
        # try to run its inherited methods with the default angr backend.
        if cls is _CLIBackendTestBase:
            raise unittest.SkipTest("abstract base class")
        if not FAUXWARE_PATH.exists():
            raise unittest.SkipTest(f"Missing test binary: {FAUXWARE_PATH}")
        if not _backend_available(cls.backend):
            raise unittest.SkipTest(f"{cls.backend} backend not available")
        os.environ["DECLIB_SERVER_REGISTRY"] = _REGISTRY_DIR
        _stop_all_servers()

    @classmethod
    def tearDownClass(cls):
        _stop_all_servers()

    def tearDown(self):
        _stop_all_servers()

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _load_fauxware(self, *extra_args, project_dir=None):
        args = ["load", str(FAUXWARE_PATH), "--backend", self.backend, "--json", *extra_args]
        if project_dir is not None:
            args.extend(["--project-dir", str(project_dir)])
        result = _run_cli(*args)
        payload = json.loads(result.stdout)
        self.assertIn(payload["status"], ("started", "already_loaded"))
        self.assertEqual(payload["backend"], self.backend)
        if payload["status"] == "started":
            self.assertIn("log_path", payload)
            self.assertTrue(Path(payload["log_path"]).is_file())
        return payload

    def _resolve_main_name(self):
        """Return whatever the current backend calls the fauxware entry.

        angr promotes the entry to ``main``; Ghidra leaves ``main`` when the
        symbol is present (fauxware is not stripped). We scan
        ``list_functions`` so the tests don't depend on any particular
        backend's naming convention.
        """
        result = _run_cli("list_functions", "--json")
        entries = json.loads(result.stdout)
        preferred = {"main", "_main"}
        for e in entries:
            if e.get("name") in preferred:
                return e["name"]
        # Fauxware's `main` entry starts at offset 0x71d (lifted).
        for e in entries:
            if e.get("addr") == 0x71d:
                return e["name"] or f"0x{e['addr']:x}"
        self.fail("Couldn't locate main in list_functions output")

    # -------------------------------------------------------------------
    # Shared backend-agnostic tests
    # -------------------------------------------------------------------

    def test_load_and_list(self):
        loaded = self._load_fauxware()
        server_id = loaded["id"]

        list_result = _run_cli("list", "--json")
        payload = json.loads(list_result.stdout)
        self.assertIn("registry_dir", payload)
        ids = {s["id"] for s in payload["servers"]}
        self.assertIn(server_id, ids)

    def test_list_functions_and_decompile(self):
        self._load_fauxware()
        lf = _run_cli("list_functions", "--json").stdout
        entries = json.loads(lf)
        self.assertTrue(entries, "list_functions returned no entries")
        for e in entries:
            self.assertIn("addr", e)
            self.assertIn("addr_hex", e)
            self.assertIn("size", e)
            self.assertIn("name", e)

        name = self._resolve_main_name()
        dec_result = _run_cli("decompile", name, "--json")
        payload = json.loads(dec_result.stdout)
        self.assertIn("text", payload)
        self.assertTrue(payload["text"], "empty decompilation")
        self.assertIn("addr_hex", payload)
        self.assertTrue(payload["addr_hex"].startswith("0x"))

    def test_disassemble(self):
        self._load_fauxware()
        name = self._resolve_main_name()
        result = _run_cli("disassemble", name, "--json")
        payload = json.loads(result.stdout)
        self.assertIn("text", payload)
        self.assertIn("addr_hex", payload)
        # Any reasonable disassembler emits at least one of these opcodes for
        # main. Compare case-insensitively so Ghidra's uppercase "PUSH" and
        # angr/capstone's lowercase "push" both pass.
        text = payload["text"].lower()
        self.assertTrue(any(op in text for op in ("push", "mov", "call", "sub")))

    def test_decompile_raw(self):
        """--raw should print text directly, not JSON-wrapped."""
        self._load_fauxware()
        name = self._resolve_main_name()
        raw = _run_cli("decompile", name, "--raw")
        self.assertNotIn('\\n', raw.stdout)
        self.assertNotIn('{"addr"', raw.stdout)

    def test_decompile_line_range(self):
        self._load_fauxware()
        name = self._resolve_main_name()
        result = _run_cli("decompile", name, "--lines", "1:2", "--json")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["bounded"])
        self.assertFalse(payload["truncated"])
        self.assertLessEqual(payload["output_lines"], 2)
        self.assertEqual(payload["source_ranges"], [{"start": 1, "end": 2}])
        self.assertLessEqual(payload["output_chars"], payload["total_chars"])

    def test_decompile_line_map(self):
        self._load_fauxware()
        name = self._resolve_main_name()
        result = _run_cli("decompile", name, "--map-lines", "--json")
        payload = json.loads(result.stdout)

        self.assertTrue(payload["line_map"], "empty decompilation line map")
        lines = [entry["line"] for entry in payload["line_map"]]
        self.assertEqual(lines, sorted(lines))
        for entry in payload["line_map"]:
            self.assertIsInstance(entry["line"], int)
            self.assertEqual(entry["addrs"], sorted(set(entry["addrs"])))
            self.assertEqual(
                entry["addrs_hex"],
                [f"0x{addr:x}" for addr in entry["addrs"]],
            )

    def test_batch_mixed_reads(self):
        """A real server executes mixed commands through one batch request."""
        self._load_fauxware()
        name = self._resolve_main_name()
        operations = [
            {"id": "functions", "argv": ["list_functions", "--filter", "auth"]},
            {"id": "decompile", "argv": ["decompile", name]},
            {"id": "header", "argv": ["read_memory", "0", "4", "--format", "hex"]},
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            batch_path = Path(tmpdir) / "operations.jsonl"
            batch_path.write_text(
                "\n".join(json.dumps(operation) for operation in operations),
                encoding="utf-8",
            )
            result = _run_cli("batch", "--file", str(batch_path), "--json")

        payload = json.loads(result.stdout)
        self.assertEqual(payload["summary"], {
            "requested": 3,
            "completed": 3,
            "failed": 0,
            "stopped_early": False,
        })
        results = {entry["id"]: entry for entry in payload["results"]}
        self.assertTrue(results["functions"]["result"])
        self.assertTrue(results["decompile"]["result"]["text"])
        self.assertEqual(results["header"]["result"]["hex"], "7f454c46")

    def test_list_strings(self):
        self._load_fauxware()
        # Every supported backend sees this string in fauxware.
        result = _run_cli("list_strings", "--filter", "Welcome", "--json")
        payload = json.loads(result.stdout)
        self.assertTrue(any("Welcome" in s["string"] for s in payload),
                        f"{self.backend} list_strings missed 'Welcome': {payload!r}")
        for entry in payload:
            # Regression for negative-address / `0x-100000` formatting — the
            # lifted hex rendering must always be a well-formed positive hex.
            self.assertTrue(entry["addr_hex"].startswith("0x"))
            self.assertNotIn("-", entry["addr_hex"][2:])

    def test_xref_to_function(self):
        self._load_fauxware()
        # `authenticate` exists in fauxware and is called from main across
        # all backends we support.
        result = _run_cli("xref_to", "authenticate", "--json")
        payload = json.loads(result.stdout)
        self.assertEqual(payload.get("target_kind"), "function")
        names = {x.get("name") for x in payload["xrefs"]}
        self.assertIn("main", names, f"{self.backend}: 'main' not in xrefs_to(authenticate): {names!r}")
        for x in payload["xrefs"]:
            self.assertIn("addr_hex", x)

    def test_xref_to_string(self):
        """Regression: xref_to should accept a string literal as target."""
        self._load_fauxware()
        # SOSNEAKY is the magic password constant in fauxware; it's
        # referenced from `authenticate`.
        result = _run_cli("xref_to", "SOSNEAKY", "--json", check=False)
        if result.returncode != 0:
            self.skipTest(f"{self.backend} doesn't surface SOSNEAKY: {result.stdout}")
        payload = json.loads(result.stdout)
        self.assertEqual(payload.get("target_kind"), "string")
        xref_names = {x.get("name") for x in payload["xrefs"]}
        self.assertIn("authenticate", xref_names,
                      f"{self.backend}: expected 'authenticate' in xref_to(SOSNEAKY): {xref_names}")

    def test_xref_from(self):
        """Regression: xref_from must return non-empty callees on each backend."""
        self._load_fauxware()
        name = self._resolve_main_name()
        result = _run_cli("xref_from", name, "--json")
        payload = json.loads(result.stdout)
        addrs = {x.get("addr") for x in payload["xrefs"]}
        self.assertGreater(len(addrs), 0, f"{self.backend}: xref_from({name}) empty")
        # Backends with debug symbols recognize at least one of these names.
        names = {x.get("name") for x in payload["xrefs"] if x.get("name")}
        self.assertTrue(names & {"authenticate", "puts", "read", "accepted", "rejected"},
                        f"{self.backend}: expected a known callee in {names}")

    def test_get_callers(self):
        self._load_fauxware()
        result = _run_cli("get_callers", "authenticate", "--json")
        payload = json.loads(result.stdout)
        names = {c.get("name") for c in payload["callers"]}
        self.assertIn("main", names)
        for c in payload["callers"]:
            self.assertIn("addr_hex", c)

    def test_read_memory(self):
        """read_memory should return the bytes at a known location.

        Fauxware's ``Welcome to the admin console, trusted user!`` string
        lives at lifted address ``0x8e0`` and the ELF header lives at the
        binary's base. Both are stable across every backend we support, so
        this is a clean cross-decompiler smoke test.
        """
        import base64

        self._load_fauxware()

        # 1. ELF magic at the binary's base. Lifted address 0x0.
        result = _run_cli("read_memory", "0x0", "0x4", "--json")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["size"], 4)
        decoded = base64.b64decode(payload["bytes_b64"])
        self.assertEqual(decoded, b"\x7fELF",
                         f"{self.backend} read_memory(0x0, 4) returned {decoded!r}")
        self.assertEqual(payload["hex"], "7f454c46")

        # 2. The "Welcome" string. Walk list_strings to find it so this
        #    isn't tied to a specific backend's address representation.
        strings = json.loads(_run_cli("list_strings", "--filter", "Welcome",
                                      "--json").stdout)
        self.assertTrue(strings, f"{self.backend}: 'Welcome' string not surfaced")
        welcome_addr = strings[0]["addr"]

        result = _run_cli("read_memory", _format_hex(welcome_addr), "7", "--json")
        payload = json.loads(result.stdout)
        self.assertEqual(base64.b64decode(payload["bytes_b64"]), b"Welcome",
                         f"{self.backend} read_memory at Welcome addr returned wrong bytes")

    def test_read_memory_hexdump_default(self):
        """Default text output is a hexdump of the bytes."""
        self._load_fauxware()
        result = _run_cli("read_memory", "0x0", "16")
        # Hexdump of the ELF header starts with the magic + class + data.
        self.assertIn("7f 45 4c 46", result.stdout)
        # ASCII column should also be present.
        self.assertIn("|.ELF", result.stdout)

    def test_read_memory_hex_format(self):
        self._load_fauxware()
        result = _run_cli("read_memory", "0x0", "4", "--format", "hex")
        self.assertEqual(result.stdout.strip(), "7f454c46")

    def test_read_memory_invalid_address(self):
        """An address far outside any segment should error cleanly."""
        self._load_fauxware()
        result = _run_cli("read_memory", "0xdeadbeef00", "16", check=False)
        self.assertNotEqual(result.returncode, 0)
        # Either the backend rejects it, or it raises before responding.
        # We just assert the CLI didn't print bytes.
        combined = result.stdout + result.stderr
        self.assertNotIn("|.ELF", combined)

    # -------------------------------------------------------------------
    # eval / exec (backend scripting escape hatch)
    # -------------------------------------------------------------------

    def test_eval_expression(self):
        self._load_fauxware_isolated()
        result = _run_cli("eval", "1 + 2", "--json")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"], "3")

    def test_eval_has_backend_access(self):
        """`deci` is bound and the backend is reachable from eval."""
        self._load_fauxware_isolated()
        result = _run_cli("eval", "len(list(deci.functions.keys())) > 0", "--json")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"], f"{self.backend}: eval failed: {payload}")
        self.assertEqual(payload["result"], "True")
        # deci.name reflects the running backend.
        name = _run_cli("eval", "deci.name", "--json")
        self.assertIn(self.backend, json.loads(name.stdout)["result"])

    def test_exec_captures_stdout(self):
        self._load_fauxware_isolated()
        result = _run_cli("exec", "print('hello from', deci.name)", "--json")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertIn("hello from", payload["stdout"])
        self.assertIn(self.backend, payload["stdout"])

    def test_exec_result_variable(self):
        self._load_fauxware_isolated()
        result = _run_cli("exec", "result = 40 + 2", "--json")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"], "42")

    def test_eval_error_is_reported(self):
        self._load_fauxware_isolated()
        result = _run_cli("eval", "1/0", "--json", check=False)
        self.assertNotEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["ok"])
        self.assertIn("ZeroDivisionError", payload["traceback"])

    # -------------------------------------------------------------------
    # patching
    # -------------------------------------------------------------------

    #: Backends that can apply byte patches.
    _patches_bytes: bool = True
    #: Backends that track patches (get/list/revert). IDA is the reference.
    _tracks_patches: bool = False

    def test_patch_set_reflects_in_memory(self):
        import base64
        self._load_fauxware_isolated()
        addr = self._main_start_addr()
        orig = base64.b64decode(json.loads(
            _run_cli("read_memory", _format_hex(addr), "4", "--json").stdout)["bytes_b64"])

        r = _run_cli("patch", "set", _format_hex(addr), "90909090", "--json", check=False)
        if not self._patches_bytes:
            self.assertNotEqual(r.returncode, 0,
                                f"{self.backend}: patch set unexpectedly succeeded")
            return
        if r.returncode != 0:
            self.skipTest(f"{self.backend}: patch set unsupported: {r.stdout + r.stderr}")
        self.assertTrue(json.loads(r.stdout)["success"])

        now = base64.b64decode(json.loads(
            _run_cli("read_memory", _format_hex(addr), "4", "--json").stdout)["bytes_b64"])
        self.assertEqual(now, b"\x90\x90\x90\x90",
                         f"{self.backend}: patched bytes not reflected in memory")

        # Revert where supported and confirm the original bytes come back.
        d = _run_cli("patch", "delete", _format_hex(addr), "--json", check=False)
        if self._tracks_patches:
            self.assertEqual(d.returncode, 0, f"{self.backend}: patch delete failed")
            reverted = base64.b64decode(json.loads(
                _run_cli("read_memory", _format_hex(addr), "4", "--json").stdout)["bytes_b64"])
            self.assertEqual(reverted, orig,
                             f"{self.backend}: patch delete did not restore original bytes")

    def test_patch_get_and_list(self):
        if not self._tracks_patches:
            self.skipTest(f"{self.backend} does not track patches")
        self._load_fauxware_isolated()
        addr = self._main_start_addr()
        setr = _run_cli("patch", "set", _format_hex(addr), "cccc", "--json", check=False)
        if setr.returncode != 0:
            self.skipTest(f"{self.backend}: patch set unsupported")
        got = json.loads(_run_cli("patch", "get", _format_hex(addr), "--json").stdout)
        self.assertTrue(got["bytes"].startswith("cccc"),
                        f"{self.backend}: patch get wrong bytes: {got}")
        listing = json.loads(_run_cli("patch", "list", "--json").stdout)
        self.assertTrue(any("cccc" in e["bytes"] for e in listing),
                        f"{self.backend}: patch not enumerated by list")

    # -------------------------------------------------------------------
    # define / undefine (code & data repair)
    # -------------------------------------------------------------------

    #: Backends that support define/undefine of code & data.
    _repairs_analysis: bool = True

    def _find_non_entry_function(self):
        """Return (addr, size) of a non-entry function safe to undefine/redefine."""
        lf = json.loads(_run_cli("list_functions", "--json").stdout)
        pref = next((e for e in lf if e.get("name") == "authenticate"), None)
        if pref is None:
            pref = next((e for e in lf if (e.get("size") or 0) > 8 and e.get("name")), None)
        return pref

    def test_undefine_and_define_function(self):
        self._load_fauxware_isolated()
        target = self._find_non_entry_function()
        if target is None:
            self.skipTest(f"{self.backend}: no suitable function")
        addr, size = target["addr"], (target.get("size") or 1)

        if not self._repairs_analysis:
            r = _run_cli("define", "function", _format_hex(addr), check=False)
            self.assertEqual(r.returncode, 2,
                             f"{self.backend}: expected unsupported (exit 2), got {r.returncode}")
            return

        # Undefine removes the function.
        u = _run_cli("undefine", _format_hex(addr), "--size", str(size), "--json", check=False)
        if u.returncode != 0:
            self.skipTest(f"{self.backend}: undefine unsupported: {u.stdout + u.stderr}")
        self.assertTrue(json.loads(u.stdout)["undefined"])

        # Re-disassemble and re-create the function (realistic repair sequence).
        # define_function reporting success is the strong signal that undefine
        # truly removed the function — add_func/createFunction only succeeds when
        # no function is already there.
        _run_cli("define", "code", _format_hex(addr), check=False)
        d = _run_cli("define", "function", _format_hex(addr), "--json", check=False)
        if d.returncode != 0:
            self.skipTest(f"{self.backend}: define function unsupported: {d.stdout + d.stderr}")
        self.assertTrue(json.loads(d.stdout)["success"],
                        f"{self.backend}: define function did not report success")
        lf3 = {e["addr"] for e in json.loads(_run_cli("list_functions", "--json").stdout)}
        self.assertIn(addr, lf3, f"{self.backend}: function not present after define")

    def test_define_data(self):
        if not self._repairs_analysis:
            self.skipTest(f"{self.backend} does not implement define/undefine")
        self._load_fauxware_isolated()
        globs = json.loads(_run_cli("global", "list", "--json").stdout)
        cand = [g for g in globs if g.get("addr", -1) >= 0]
        if not cand:
            self.skipTest(f"{self.backend}: no global address to define data on")
        addr = cand[0]["addr"]
        r = _run_cli("define", "data", _format_hex(addr), "--type", "int", "--json", check=False)
        if r.returncode != 0:
            self.skipTest(f"{self.backend}: define data unsupported: {r.stdout + r.stderr}")
        self.assertTrue(json.loads(r.stdout)["success"])

    # -------------------------------------------------------------------
    # search + imports
    # -------------------------------------------------------------------

    #: Backends with a native byte-search API (angr has none).
    _searches_bytes: bool = True
    #: Backends that enumerate imports.
    _lists_imports: bool = True

    def test_search_bytes_elf_magic(self):
        if not self._searches_bytes:
            self.skipTest(f"{self.backend} has no byte-search API")
        self._load_fauxware_isolated()
        result = _run_cli("search", "bytes", "7f454c46", "--json", check=False)
        if result.returncode == 2:
            self.skipTest(f"{self.backend}: search bytes unsupported")
        payload = json.loads(result.stdout)
        self.assertGreaterEqual(payload["count"], 1,
                                f"{self.backend}: ELF magic not found by search bytes")
        # The ELF magic sits at the image base -> lifted 0x0.
        addrs = {m["addr"] for m in payload["matches"]}
        self.assertIn(0, addrs, f"{self.backend}: expected a match at lifted 0x0: {addrs}")

    def test_search_string(self):
        if not self._searches_bytes:
            self.skipTest(f"{self.backend} has no byte-search API")
        self._load_fauxware_isolated()
        result = _run_cli("search", "string", "SOSNEAKY", "--json", check=False)
        if result.returncode == 2:
            self.skipTest(f"{self.backend}: search string unsupported")
        payload = json.loads(result.stdout)
        self.assertGreaterEqual(payload["count"], 1,
                                f"{self.backend}: 'SOSNEAKY' not found in memory")

    def test_search_instruction(self):
        """Instruction search is client-side (disasm grep) — works on all backends."""
        self._load_fauxware_isolated()
        result = _run_cli("search", "instruction", r"call", "--max", "50", "--json")
        payload = json.loads(result.stdout)
        self.assertGreaterEqual(payload["count"], 1,
                                f"{self.backend}: no 'call' instructions found")
        for m in payload["matches"]:
            self.assertIn("call", m["line"].lower())

    def test_imports_list(self):
        if not self._lists_imports:
            self.skipTest(f"{self.backend} does not enumerate imports")
        self._load_fauxware_isolated()
        result = _run_cli("imports", "--json", check=False)
        if result.returncode == 2:
            self.skipTest(f"{self.backend}: imports unsupported")
        entries = json.loads(result.stdout)
        names = {e["name"] for e in entries}
        # fauxware imports libc functions; at least one of these is always present.
        self.assertTrue(any(n and any(k in n for k in ("puts", "read", "printf", "strcmp"))
                            for n in names),
                        f"{self.backend}: expected a libc import in {names}")

    # -------------------------------------------------------------------
    # typed reads + address semantics
    # -------------------------------------------------------------------

    def test_read_int_elf_magic(self):
        """`read int` decodes the ELF magic word at the image base (lifted 0x0)."""
        self._load_fauxware_isolated()
        # Big-endian 4 bytes at 0x0 == 0x7f454c46 ("\x7fELF").
        result = _run_cli("read", "int", "0x0", "--size", "4", "--endian", "big", "--json")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["value"], 0x7f454c46,
                         f"{self.backend}: read int gave {payload['value']:#x}")
        # Little-endian reversal.
        le = json.loads(_run_cli("read", "int", "0x0", "--size", "4", "--json").stdout)
        self.assertEqual(le["value"], 0x464c457f)

    def test_read_string(self):
        self._load_fauxware_isolated()
        strings = json.loads(_run_cli("list_strings", "--filter", "Welcome", "--json").stdout)
        self.assertTrue(strings, f"{self.backend}: 'Welcome' string not surfaced")
        addr = strings[0]["addr"]
        result = _run_cli("read", "string", _format_hex(addr), "--json")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["string"].startswith("Welcome"),
                        f"{self.backend}: read string gave {payload['string']!r}")

    def test_read_struct(self):
        """Define a struct and decode the ELF header bytes through it."""
        self._load_fauxware_isolated()
        rc = _run_cli("create-type", "struct ElfMagic { int magic; short type; }",
                      "--json", check=False)
        if rc.returncode != 0 or not json.loads(rc.stdout).get("success"):
            self.skipTest(f"{self.backend}: could not define struct: {rc.stdout + rc.stderr}")
        result = _run_cli("read", "struct", "0x0", "ElfMagic", "--json", check=False)
        if result.returncode != 0:
            self.skipTest(f"{self.backend}: read struct unsupported: {result.stdout + result.stderr}")
        payload = json.loads(result.stdout)
        members = {m["name"]: m for m in payload["members"]}
        self.assertIn("magic", members)
        # Little-endian int of "\x7fELF" == 0x464c457f.
        self.assertEqual(members["magic"]["value"], 0x464c457f,
                         f"{self.backend}: struct member decode wrong: {members['magic']}")

    def test_read_memory_absolute_and_lifted_agree(self):
        """Regression for double-base-add: absolute and lifted addrs read the same byte."""
        import base64
        self._load_fauxware_isolated()
        client = self._direct_client()
        try:
            base = client.binary_base_addr
        finally:
            client.shutdown()
        # Lifted 0x0 -> ELF magic.
        lifted = json.loads(_run_cli("read_memory", "0x0", "4", "--json").stdout)
        self.assertEqual(base64.b64decode(lifted["bytes_b64"]), b"\x7fELF")
        if not base:
            self.skipTest(f"{self.backend}: image base is 0; absolute == lifted")
        # Absolute (base + 0) must resolve to the same bytes, not double-add base.
        absolute = _run_cli("read_memory", _format_hex(base), "4", "--json", check=False)
        self.assertEqual(absolute.returncode, 0,
                         f"{self.backend}: absolute read failed: {absolute.stdout + absolute.stderr}")
        self.assertEqual(base64.b64decode(json.loads(absolute.stdout)["bytes_b64"]), b"\x7fELF",
                         f"{self.backend}: absolute address didn't normalize to lifted")

    #: Subclasses set this to True if their backend actually persists files
    #: (Ghidra project, IDA database, etc). For in-memory backends like angr
    #: it stays False and we only assert "nothing wound up next to the binary".
    _persists_project_files: bool = False

    def test_project_dir_keeps_binary_dir_clean(self):
        """`--project-dir` should make the backend write its DB outside the binary's dir."""
        with tempfile.TemporaryDirectory() as project_dir, tempfile.TemporaryDirectory() as bin_dir:
            # Copy fauxware into an isolated directory so we can verify
            # nothing gets written beside it.
            local_bin = Path(bin_dir) / "fauxware"
            shutil.copyfile(FAUXWARE_PATH, local_bin)
            local_bin.chmod(0o755)
            before = set(os.listdir(bin_dir))

            _run_cli("load", str(local_bin), "--backend", self.backend,
                     "--project-dir", project_dir, "--json")
            # Give the backend a beat to finish writing.
            _run_cli("list_functions", "--json")

            after = set(os.listdir(bin_dir))
            new_files = after - before
            self.assertFalse(new_files,
                             f"{self.backend} wrote unexpected files beside the binary: {new_files}")
            # Backends that actually persist project state (Ghidra, IDA) should
            # have written *something* to the override dir; in-memory backends
            # (angr) correctly produce no files and that's the whole point —
            # there's nothing to place anywhere.
            if self._persists_project_files:
                project_contents = list(Path(project_dir).rglob("*"))
                self.assertTrue(project_contents,
                                f"{self.backend} wrote nothing to the project_dir")

    # -------------------------------------------------------------------
    # Persistence: explicit save + stop --save/--discard, reopen-and-verify
    # -------------------------------------------------------------------

    def _isolated_proj(self):
        """A fresh, dot-free project dir (Ghidra rejects dot-prefixed paths)."""
        proj = tempfile.mkdtemp(prefix="declib_persist_proj_")
        self.addCleanup(shutil.rmtree, proj, ignore_errors=True)
        return proj

    def test_save_unsupported_on_inmemory_backend(self):
        """Backends with no on-disk database report `save` as unsupported (exit 2)."""
        if self._persists_project_files:
            self.skipTest(f"{self.backend} persists to disk; covered by reopen tests")
        self._load_fauxware()
        result = _run_cli("save", "--json", check=False)
        self.assertEqual(result.returncode, 2,
                         f"{self.backend}: expected unsupported exit 2, got {result.returncode}: "
                         f"{result.stdout + result.stderr}")
        self.assertIn("not implemented", (result.stdout + result.stderr).lower())

    def test_save_command_persists_rename_across_reload(self):
        """`save` then stop then reload (same project-dir) keeps a function rename."""
        if not self._persists_project_files:
            self.skipTest(f"{self.backend} is in-memory; nothing to persist")
        proj = self._isolated_proj()
        loaded = self._load_fauxware(project_dir=proj)
        server_id = loaded["id"]

        new_name = "persisted_via_save"
        renamed = _run_cli("rename", "func", "authenticate", new_name, "--json")
        self.assertTrue(json.loads(renamed.stdout)["success"],
                        f"{self.backend}: rename failed: {renamed.stdout}")

        saved = _run_cli("save", "--json")
        self.assertTrue(json.loads(saved.stdout)["saved"],
                        f"{self.backend}: save reported failure: {saved.stdout}")

        _run_cli("stop", "--id", server_id, "--json")

        # Reopen the same project dir in a fresh server and confirm the rename
        # survived the round-trip to disk.
        self._load_fauxware(project_dir=proj)
        listing = json.loads(_run_cli("list_functions", "--filter", new_name, "--json").stdout)
        names = {e["name"] for e in listing}
        self.assertIn(new_name, names,
                      f"{self.backend}: rename did not persist across reload; saw {names}")

    def test_stop_save_persists_rename_across_reload(self):
        """`stop --save` flushes to disk so a reload sees the rename."""
        if not self._persists_project_files:
            self.skipTest(f"{self.backend} is in-memory; nothing to persist")
        proj = self._isolated_proj()
        loaded = self._load_fauxware(project_dir=proj)
        server_id = loaded["id"]

        new_name = "persisted_via_stop_save"
        renamed = _run_cli("rename", "func", "authenticate", new_name, "--json")
        self.assertTrue(json.loads(renamed.stdout)["success"])

        stopped = _run_cli("stop", "--id", server_id, "--save", "--json")
        self.assertTrue(json.loads(stopped.stdout)["stopped"][0]["stopped"])

        self._load_fauxware(project_dir=proj)
        listing = json.loads(_run_cli("list_functions", "--filter", new_name, "--json").stdout)
        names = {e["name"] for e in listing}
        self.assertIn(new_name, names,
                      f"{self.backend}: rename did not persist via stop --save; saw {names}")

    def test_stop_save_and_discard_are_mutually_exclusive(self):
        loaded = self._load_fauxware()
        result = _run_cli("stop", "--id", loaded["id"], "--save", "--discard", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mutually exclusive", result.stdout + result.stderr)

    # -------------------------------------------------------------------
    # comment CRUD
    # -------------------------------------------------------------------

    #: Backends that can read comments back (angr only implements set today).
    _reads_comments: bool = True

    def _main_start_addr(self):
        """Lifted start address of fauxware's main across backends."""
        entries = json.loads(_run_cli("list_functions", "--json").stdout)
        for e in entries:
            if e.get("name") in ("main", "_main"):
                return e["addr"]
        for e in entries:
            if e.get("addr") == 0x71d:
                return e["addr"]
        self.fail("couldn't find main for comment test")

    def test_comment_set_get(self):
        self._load_fauxware_isolated()
        addr = self._main_start_addr()
        text = "declib annotated this"
        setr = _run_cli("comment", "set", _format_hex(addr), text, "--json", check=False)
        if setr.returncode != 0:
            self.skipTest(f"{self.backend}: comment set unsupported here: {setr.stdout + setr.stderr}")
        self.assertTrue(json.loads(setr.stdout)["success"])

        if not self._reads_comments:
            self.skipTest(f"{self.backend} does not implement comment reads")
        got = _run_cli("comment", "get", _format_hex(addr), "--json")
        self.assertIn(text, json.loads(got.stdout)["comment"],
                      f"{self.backend}: comment get did not return the set text")

    def test_comment_append(self):
        if not self._reads_comments:
            self.skipTest(f"{self.backend} does not implement comment reads")
        self._load_fauxware_isolated()
        addr = self._main_start_addr()
        first = _run_cli("comment", "set", _format_hex(addr), "first line", "--json", check=False)
        if first.returncode != 0:
            self.skipTest(f"{self.backend}: comment set unsupported here")
        _run_cli("comment", "append", _format_hex(addr), "second line", "--json")
        got = json.loads(_run_cli("comment", "get", _format_hex(addr), "--json").stdout)
        self.assertIn("first line", got["comment"])
        self.assertIn("second line", got["comment"])

    def test_comment_list_and_delete(self):
        if not self._reads_comments:
            self.skipTest(f"{self.backend} does not implement comment reads")
        self._load_fauxware_isolated()
        addr = self._main_start_addr()
        marker = "UNIQUE_COMMENT_MARKER_XYZ"
        setr = _run_cli("comment", "set", _format_hex(addr), marker, "--json", check=False)
        if setr.returncode != 0:
            self.skipTest(f"{self.backend}: comment set unsupported here")

        listing = json.loads(_run_cli("comment", "list", "--filter", marker, "--json").stdout)
        self.assertTrue(any(marker in e["comment"] for e in listing),
                        f"{self.backend}: set comment not enumerated by `comment list`")

        deleted = _run_cli("comment", "delete", _format_hex(addr), "--json")
        self.assertTrue(json.loads(deleted.stdout)["deleted"])
        after = _run_cli("comment", "get", _format_hex(addr), check=False)
        self.assertNotEqual(after.returncode, 0,
                            f"{self.backend}: comment still present after delete")

    def test_comment_get_missing_exits_nonzero(self):
        self._load_fauxware_isolated()
        addr = self._main_start_addr()
        # Clear anything at main's entry, then a get there must report "missing".
        # (Deterministic across backends without depending on auto-comment layout.)
        _run_cli("comment", "delete", _format_hex(addr), check=False)
        result = _run_cli("comment", "get", _format_hex(addr), check=False)
        self.assertNotEqual(result.returncode, 0)

    # -------------------------------------------------------------------
    # global variables
    # -------------------------------------------------------------------

    #: Backends that implement global-variable listing/reading.
    _reads_globals: bool = True

    def test_global_list(self):
        if not self._reads_globals:
            self.skipTest(f"{self.backend} does not implement global enumeration")
        self._load_fauxware_isolated()
        listing = json.loads(_run_cli("global", "list", "--json").stdout)
        self.assertTrue(listing, f"{self.backend}: `global list` returned nothing")
        for e in listing:
            self.assertIn("addr", e)
            self.assertIn("name", e)

    def test_global_rename(self):
        if not self._reads_globals:
            self.skipTest(f"{self.backend} does not implement globals")
        self._load_fauxware_isolated()
        listing = json.loads(_run_cli("global", "list", "--json").stdout)
        # Pick a real, addressable global (positive lifted addr + a name).
        candidates = [g for g in listing if g.get("addr", -1) >= 0 and g.get("name")]
        if not candidates:
            self.skipTest(f"{self.backend}: no renameable globals")
        target = candidates[0]
        renamed = _run_cli("global", "rename", _format_hex(target["addr"]),
                           "renamed_global_xyz", "--json", check=False)
        if renamed.returncode != 0:
            self.skipTest(f"{self.backend}: global rename unsupported: {renamed.stdout + renamed.stderr}")
        payload = json.loads(renamed.stdout)
        self.assertTrue(payload["success"])
        self.assertEqual(payload["name"], "renamed_global_xyz",
                         f"{self.backend}: global rename didn't stick")

    # -------------------------------------------------------------------
    # function signatures
    # -------------------------------------------------------------------

    def test_signature_get(self):
        self._load_fauxware_isolated()
        name = self._resolve_main_name()
        result = _run_cli("signature", "get", name, "--json")
        payload = json.loads(result.stdout)
        self.assertIn("signature", payload)
        self.assertIn("(", payload["signature"])
        self.assertIsNotNone(payload.get("return_type"))

    #: Backends that apply return/argument *types* via signature set (angr sets
    #: only argument names today).
    _sets_signature_types: bool = True

    def test_signature_set(self):
        self._load_fauxware_isolated()
        name = self._resolve_main_name()
        result = _run_cli("signature", "set", name, "long main(int argc, char **argv)",
                          "--json", check=False)
        if result.returncode != 0:
            self.skipTest(f"{self.backend}: signature set unsupported: {result.stdout + result.stderr}")
        self.assertTrue(json.loads(result.stdout)["success"])
        if not self._sets_signature_types:
            self.skipTest(f"{self.backend} sets arg names but not types via signature set")
        # Verify the changed return type shows up on a fresh read.
        got = json.loads(_run_cli("signature", "get", name, "--json").stdout)
        self.assertIn("long", (got.get("return_type") or "").lower(),
                      f"{self.backend}: signature set return type not reflected: {got}")

    def test_signature_get_missing_exits_nonzero(self):
        self._load_fauxware_isolated()
        result = _run_cli("signature", "get", "no_such_function_xyz", check=False)
        self.assertEqual(result.returncode, 1)

    # -------------------------------------------------------------------
    # create-type / retype (run against every backend)
    # -------------------------------------------------------------------

    def _direct_client(self):
        """Connect a DecompilerClient straight to this binary's server."""
        record = server_registry.find_servers(binary_path=str(FAUXWARE_PATH))[0]
        return DecompilerClient(socket_path=record["socket_path"])

    def _load_fauxware_isolated(self):
        """Load fauxware into a fresh, non-hidden project dir.

        Ghidra rejects project *locations* containing a dot-prefixed path
        element (e.g. the default ``~/.cache/declib/...``), so hand it a temp
        dir. This also keeps the test hermetic — no shared-cache state leaks
        in from prior (possibly interrupted) runs.
        """
        proj = tempfile.mkdtemp(prefix="declib_cli_proj_")
        self.addCleanup(shutil.rmtree, proj, ignore_errors=True)
        return self._load_fauxware(project_dir=proj)

    def test_create_type(self):
        self._load_fauxware_isolated()
        result = _run_cli("create-type", "struct Point { int x; int y; }", "--json")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["kind"], "Struct")
        self.assertEqual(payload["name"], "Point")
        self.assertTrue(payload["success"],
                        f"{self.backend}: create-type failed: {payload}")

        # Verify the struct actually landed, with both named members.
        client = self._direct_client()
        try:
            struct = client.structs["Point"]
        finally:
            client.shutdown()
        self.assertIsNotNone(struct, f"{self.backend}: Point not found after create")
        member_names = {m.name for m in struct.members.values()}
        self.assertEqual(member_names, {"x", "y"},
                         f"{self.backend}: unexpected members {member_names}")

    def test_retype(self):
        self._load_fauxware_isolated()
        # Pick a 4-byte scalar stack var (an int) and retype it to `float`.
        # Same size + scalar->scalar keeps this clean across backends: no
        # overlap with the adjacent slot and no array->scalar reshaping (which
        # Ghidra handles poorly).
        client = self._direct_client()
        try:
            addrs = [a for a, f in client.functions.items() if f.name == "main"]
            main_addr = addrs[0]
            main_func = client.functions[main_addr]
            svars = list(main_func.stack_vars.values())
            scalars = [v for v in svars
                       if (v.size or 0) == 4 and "[" not in str(v.type or "")]
            if not scalars:
                self.skipTest(f"{self.backend}: no 4-byte scalar var in main to retype")
            target = scalars[0].name
            had_float_before = any("float" in str(v.type or "").lower() for v in svars)
        finally:
            client.shutdown()
        self.assertFalse(had_float_before,
                         f"{self.backend}: main already has a float var; bad fixture")

        result = _run_cli("retype", "main", target, "float", "--json", check=False)
        if result.returncode != 0:
            self.skipTest(
                f"{self.backend}: retype of {target!r} unsupported: "
                f"{result.stdout + result.stderr}"
            )
        self.assertTrue(json.loads(result.stdout)["success"])

        # Verify a float-typed variable now exists. Match on the type appearing
        # in the set rather than by name/offset: backends rename a variable by
        # its type when retyped (Ghidra local_2c -> fStack_2c).
        client = self._direct_client()
        try:
            refreshed = client.functions[main_addr]
            after_types = [str(v.type or "").lower() for v in refreshed.stack_vars.values()]
        finally:
            client.shutdown()
        self.assertTrue(any("float" in t for t in after_types),
                        f"{self.backend}: no float-typed var after retype; types={after_types}")

    def test_retype_missing_var_exits_1(self):
        self._load_fauxware_isolated()
        result = _run_cli("retype", "main", "no_such_var_xyz", "int", check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("not found", (result.stdout + result.stderr).lower())


class TestDecompilerCLIAngr(_CLIBackendTestBase):
    """angr backend: always available (pure-Python dependency)."""
    backend = "angr"
    # angr implements comment *writes* but not reads/enumeration yet.
    _reads_comments = False
    # angr has no first-class global-variable store.
    _reads_globals = False
    # angr's signature set applies argument names but not types/return type.
    _sets_signature_types = False
    # angr has no native byte-search API (instruction search still works —
    # it's client-side). It does enumerate imports via the cle loader.
    _searches_bytes = False
    # angr's CFG-based model has no define/undefine primitives.
    _repairs_analysis = False
    # angr has no user-patch store.
    _patches_bytes = False

    # angr-specific sanity checks that don't map cleanly to the other
    # backends live here.
    def test_load_idempotent(self):
        first = self._load_fauxware()
        second = self._load_fauxware()
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(second["status"], "already_loaded")

    def test_multi_instance_same_binary_with_force(self):
        first = self._load_fauxware()
        forced = _run_cli("load", str(FAUXWARE_PATH), "--backend", "angr",
                          "--force", "--json")
        second = json.loads(forced.stdout)
        self.assertNotEqual(first["id"], second["id"])

        # Ambiguous selection should fail helpfully.
        result = _run_cli("decompile", "main", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Specify --id", result.stdout + result.stderr)

        # Selecting a specific id disambiguates.
        ok = _run_cli("decompile", "main", "--id", first["id"])
        self.assertIn("main", ok.stdout)

    def test_load_replace_stops_old_server(self):
        first = self._load_fauxware()
        replaced_result = _run_cli("load", str(FAUXWARE_PATH), "--backend", "angr",
                                   "--replace", "--json")
        replaced = json.loads(replaced_result.stdout)
        self.assertEqual(replaced["status"], "started")
        self.assertNotEqual(replaced["id"], first["id"])
        listing = _run_cli("list", "--json")
        servers = json.loads(listing.stdout)["servers"]
        fauxware_servers = [s for s in servers if s["binary_path"] == str(FAUXWARE_PATH)]
        self.assertEqual(len(fauxware_servers), 1)
        self.assertEqual(fauxware_servers[0]["id"], replaced["id"])

    def test_client_disconnect_does_not_tear_down_server(self):
        """Regression: a client context-exiting must not close the server's project.

        Each `decompiler <cmd>` spawns a fresh client, uses it via `with`, and
        exits. If the client's `shutdown()` sends `shutdown_deci` to the server,
        the next invocation hits a closed program (ClosedException on ghidra).
        """
        self._load_fauxware()
        for _ in range(3):
            result = _run_cli("decompile", "main", "--json")
            payload = json.loads(result.stdout)
            self.assertIn("text", payload)

    def test_decompile_not_a_function_start(self):
        self._load_fauxware()
        result = _run_cli("decompile", "0x71e", check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("No function starts at", result.stdout + result.stderr)

    def test_rename_func(self):
        self._load_fauxware()
        result = _run_cli("rename", "func", "authenticate", "my_auth", "--json")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["success"])

    def test_rename_func_missing_exits_1(self):
        self._load_fauxware()
        result = _run_cli("rename", "func", "nonexistent_fn_xyz", "whatever",
                          check=False)
        self.assertEqual(result.returncode, 1)

    def test_rename_var_missing_exits_1(self):
        self._load_fauxware()
        result = _run_cli("rename", "var", "no_such_var_xyz", "whatever",
                          "--function", "main", check=False)
        self.assertEqual(result.returncode, 1)

    def test_rename_var(self):
        self._load_fauxware()
        record = server_registry.find_servers(binary_path=str(FAUXWARE_PATH))[0]
        client = DecompilerClient(socket_path=record["socket_path"])
        try:
            addrs = [a for a, f in client.functions.items() if f.name == "main"]
            main_addr = addrs[0]
            main_func = client.functions[main_addr]
            names = client.local_variable_names(main_func)
            target = next((n for n in names if n not in ("a0", "a1")), names[0])
        finally:
            client.shutdown()

        result = _run_cli("rename", "var", target, "renamed_var",
                          "--function", "main", "--json")
        payload = json.loads(result.stdout)
        self.assertTrue(payload["success"])

    def test_list_strings_min_length(self):
        self._load_fauxware()
        result = _run_cli("list_strings", "--min-length", "20", "--json")
        entries = json.loads(result.stdout)
        for e in entries:
            self.assertGreaterEqual(len(e["string"]), 20)

    def test_stop(self):
        loaded = self._load_fauxware()
        stop = _run_cli("stop", "--id", loaded["id"], "--json")
        payload = json.loads(stop.stdout)
        self.assertTrue(payload["stopped"][0]["stopped"])
        listing = _run_cli("list", "--json")
        ids = {s["id"] for s in json.loads(listing.stdout)["servers"]}
        self.assertNotIn(loaded["id"], ids)

    @unittest.skipUnless(POSIX_SYSCALL_PATH.exists(), f"Missing: {POSIX_SYSCALL_PATH}")
    def test_two_binaries_concurrent(self):
        first = self._load_fauxware()
        second_result = _run_cli("load", str(POSIX_SYSCALL_PATH), "--backend", "angr", "--json")
        second = json.loads(second_result.stdout)
        self.assertNotEqual(first["id"], second["id"])
        fauxware_strings = _run_cli("list_strings", "--id", first["id"], "--json")
        self.assertTrue(any("Welcome" in s["string"]
                            for s in json.loads(fauxware_strings.stdout)))


@unittest.skipUnless(_backend_available("ghidra"),
                     "ghidra backend not available (no GHIDRA_INSTALL_DIR or pyghidra missing)")
class TestDecompilerCLIGhidra(_CLIBackendTestBase):
    """Ghidra backend: same suite as angr, running against real Ghidra."""
    backend = "ghidra"
    _persists_project_files = True  # Ghidra writes its project under --project-dir

    def test_list_strings_picks_up_uchar_array(self):
        """Regression: Ghidra auto-types the base64 alphabet as `uchar[64]`
        rather than a string, so ``getDefinedData`` misses it. The
        supplemental StringSearcher pass should surface it anyway.

        Skips when the challenge binary isn't checked in (it only ships in
        the repo for local reproduction). Using ``pathlib`` rather than
        copying the binary into TEST_BINARIES_DIR keeps the repo tidy.
        """
        challenge = Path(__file__).parent.parent / "challenge" / "rpc.out"
        if not challenge.exists():
            self.skipTest(f"challenge binary missing: {challenge}")
        _run_cli("load", str(challenge), "--backend", "ghidra", "--json")
        result = _run_cli("list_strings", "--filter", "ABCDEFGHIJKLMN", "--json")
        payload = json.loads(result.stdout)
        self.assertTrue(
            any("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                in s["string"] for s in payload),
            f"Ghidra list_strings missed the base64 alphabet: {payload!r}"
        )


@unittest.skipUnless(_backend_available("ida"),
                     "ida backend not available (idapro module missing)")
class TestDecompilerCLIIDA(_CLIBackendTestBase):
    """IDA (via idalib) backend: same suite as angr, running against real IDA.

    Mostly a regression test for main-thread dispatch: idalib rejects every
    cross-thread API call with ``Function can be called from the main thread
    only``, so every CLI round-trip here exercises the dispatcher path —
    the client's ``server_info`` handshake included.
    """
    backend = "ida"
    _persists_project_files = True  # .id0/.id1/.id2/.nam/.til
    _tracks_patches = True  # IDA records patched bytes and can revert them


# ---------------------------------------------------------------------------
# Cross-decompiler sync: push edits made in IDA into a running Ghidra instance.
# Standalone (not backend-parametrized) because it needs two specific backends.
# ---------------------------------------------------------------------------

@unittest.skipUnless(
    _backend_available("ida") and _backend_available("ghidra"),
    "sync IDA->Ghidra tests need both ida (idapro) and ghidra (GHIDRA_INSTALL_DIR)",
)
class TestDecompilerSyncIDAtoGhidra(unittest.TestCase):
    """`decompiler sync` copies a function's work from a source server (IDA)
    into a destination server (Ghidra) for the same binary."""

    @classmethod
    def setUpClass(cls):
        if not FAUXWARE_PATH.exists():
            raise unittest.SkipTest(f"Missing test binary: {FAUXWARE_PATH}")
        os.environ["DECLIB_SERVER_REGISTRY"] = _REGISTRY_DIR
        _stop_all_servers()

    @classmethod
    def tearDownClass(cls):
        _stop_all_servers()

    def setUp(self):
        # Fresh, isolated project dir per test so a stale/locked backend
        # database from a previous (possibly interrupted) run can't make a
        # `load` hang or fail. Each backend writes into its own subdir.
        self._proj_dir = tempfile.mkdtemp(prefix="declib_sync_proj_")

    def tearDown(self):
        _stop_all_servers()
        shutil.rmtree(self._proj_dir, ignore_errors=True)

    # -- helpers -----------------------------------------------------------

    def _load(self, backend):
        # `load` blocks until the server is ready (Ghidra analysis included).
        out = _run_cli("load", str(FAUXWARE_PATH), "--backend", backend,
                       "--force", "--project-dir", self._proj_dir, "--json").stdout
        payload = json.loads(out)
        self.assertIn(payload["status"], ("started", "already_loaded"))
        return payload["id"]

    def _client_for(self, server_id):
        rec = server_registry.find_server(server_id=server_id)
        self.assertIsNotNone(rec, f"no server record for id={server_id}")
        return DecompilerClient(socket_path=rec["socket_path"])

    def _main_addr(self, client):
        addrs = [a for a, f in client.functions.items()
                 if f.name in ("main", "_main")]
        if not addrs:
            addrs = [a for a in client.functions.keys() if a == 0x71d]
        self.assertTrue(addrs, "could not find main on server")
        return addrs[0]

    # -- tests -------------------------------------------------------------

    def test_sync_names_ida_to_ghidra(self):
        ida_id = self._load("ida")
        ghidra_id = self._load("ghidra")

        # Pick a stack var on the IDA side to rename.
        ida = self._client_for(ida_id)
        try:
            main_addr = self._main_addr(ida)
            main_func = ida.functions[main_addr]
            self.assertTrue(main_func.stack_vars, "IDA main has no stack vars")
            target_off = sorted(main_func.stack_vars.keys())[0]
            old_var_name = main_func.stack_vars[target_off].name
        finally:
            ida.shutdown()

        # Edit in IDA via the CLI: rename the function and the stack var.
        # Reference the function by address (stable) rather than by its new
        # name, since the light function list can lag a header rename.
        main_hex = _format_hex(main_addr)
        r1 = _run_cli("rename", "func", main_hex, "synced_main", "--id", ida_id, "--json")
        self.assertTrue(json.loads(r1.stdout)["success"])
        r2 = _run_cli("rename", "var", old_var_name, "synced_var",
                      "--function", main_hex, "--id", ida_id, "--json")
        self.assertTrue(json.loads(r2.stdout)["success"])

        # Sync IDA -> Ghidra (sync takes a function address).
        rs = _run_cli("sync", main_hex, "--from-id", ida_id,
                      "--id", ghidra_id, "--json")
        sync_payload = json.loads(rs.stdout)
        self.assertTrue(sync_payload["success"], f"sync failed: {sync_payload}")

        # Verify on Ghidra. The function is keyed by addr (Ghidra still calls
        # it "main"); the renamed var is matched by canonical stack offset.
        ghidra = self._client_for(ghidra_id)
        try:
            gfunc = ghidra.functions[sync_payload["addr"]]
            self.assertEqual(gfunc.name, "synced_main",
                             f"function name not synced: {gfunc.name}")
            var_names = {sv.name for sv in gfunc.stack_vars.values()}
            self.assertIn("synced_var", var_names,
                          f"variable name not synced; ghidra vars: {var_names}")
        finally:
            ghidra.shutdown()

    def test_sync_types_ida_to_ghidra(self):
        ida_id = self._load("ida")
        ghidra_id = self._load("ghidra")

        # Pick a stack var on IDA to retype. Use the largest so there's room
        # for an 8-byte `Point *` without overlapping the adjacent slot.
        ida = self._client_for(ida_id)
        try:
            main_addr = self._main_addr(ida)
            main_func = ida.functions[main_addr]
            self.assertTrue(main_func.stack_vars)
            biggest = max(main_func.stack_vars.values(), key=lambda v: (v.size or 0))
            target_off = biggest.offset
            target_var_name = biggest.name
        finally:
            ida.shutdown()

        # Feature 1 in IDA: create a struct, then retype a var to a Point pointer.
        rc = _run_cli("create-type", "struct Point { int x; int y; }",
                      "--id", ida_id, "--json")
        self.assertEqual(rc.returncode, 0, rc.stderr)
        self.assertTrue(json.loads(rc.stdout)["success"])
        main_hex = _format_hex(main_addr)
        rt = _run_cli("retype", main_hex, target_var_name, "Point *",
                      "--id", ida_id, "--json")
        self.assertEqual(rt.returncode, 0, rt.stderr)
        self.assertTrue(json.loads(rt.stdout)["success"])

        # Sync IDA -> Ghidra (sync takes a function address).
        rs = _run_cli("sync", main_hex, "--from-id", ida_id, "--id", ghidra_id, "--json")
        sync_payload = json.loads(rs.stdout)
        self.assertTrue(sync_payload["success"], f"sync failed: {sync_payload}")

        # Verify on Ghidra: the struct exists and the var references it.
        ghidra = self._client_for(ghidra_id)
        try:
            self.assertIn("Point", ghidra.structs,
                          f"Point not in ghidra structs: {list(ghidra.structs.keys())}")
            gfunc = ghidra.functions[sync_payload["addr"]]
            point_typed = [sv for sv in gfunc.stack_vars.values()
                           if "Point" in str(sv.type or "")]
            self.assertTrue(point_typed,
                            "no ghidra var references Point: "
                            f"{[(sv.name, sv.type) for sv in gfunc.stack_vars.values()]}")
        finally:
            ghidra.shutdown()


# ---------------------------------------------------------------------------
# Type-definition parser unit tests: backend-free, cheap to iterate on.
# ---------------------------------------------------------------------------

class TestTypeDefinitionParser(unittest.TestCase):
    def test_struct_offsets_and_size(self):
        from declib.api.type_definition_parser import parse_type_definition
        s = parse_type_definition("struct Point { int x; int y; }")
        self.assertEqual(s.name, "Point")
        self.assertEqual(s.members[0].name, "x")
        self.assertEqual(s.members[0].size, 4)
        self.assertEqual(s.members[4].name, "y")
        self.assertEqual(s.size, 8)

    def test_struct_pointer_and_array_members(self):
        from declib.api.type_definition_parser import parse_type_definition
        s = parse_type_definition("struct S { char *name; int arr[4]; struct Foo *fp; }")
        types = {m.name: m.type for m in s.members.values()}
        self.assertEqual(types["name"], "char *")
        self.assertEqual(types["arr"], "int [4]")
        self.assertEqual(types["fp"], "struct Foo *")

    def test_enum(self):
        from declib.api.type_definition_parser import parse_type_definition
        e = parse_type_definition("enum Color { RED, GREEN=5, BLUE }")
        self.assertEqual(dict(e.members), {"RED": 0, "GREEN": 5, "BLUE": 6})

    def test_typedef(self):
        from declib.api.type_definition_parser import parse_type_definition
        t = parse_type_definition("typedef char *str_t")
        self.assertEqual(t.name, "str_t")
        self.assertEqual(t.type, "char *")

    def test_bad_input_raises(self):
        from declib.api.type_definition_parser import (
            parse_type_definition, TypeDefinitionParseError,
        )
        for bad in ["struct {", "not c @#", "", "struct Empty {}",
                    "struct A { int a; }; struct B { int b; };"]:
            with self.assertRaises(TypeDefinitionParseError):
                parse_type_definition(bad)


# ---------------------------------------------------------------------------
# Artifact-serialization unit tests: keep these separate from the CLI
# subprocess tests so they run in isolation and are cheap to iterate on.
# ---------------------------------------------------------------------------

class TestPrototypeParser(unittest.TestCase):
    """Backend-free tests for the C prototype parser/formatter."""

    def test_parse_basic(self):
        from declib.api.prototype import parse_prototype
        ret, args = parse_prototype("int main(int argc, char **argv)")
        self.assertEqual(ret, "int")
        self.assertEqual(args, [("int", "argc"), ("char **", "argv")])

    def test_parse_pointer_return_and_varargs(self):
        from declib.api.prototype import parse_prototype
        ret, args = parse_prototype("char *printf(const char *fmt, ...)")
        self.assertEqual(ret, "char *")
        self.assertEqual(args[0], ("const char *", "fmt"))
        self.assertEqual(args[1], ("...", None))

    def test_parse_void_args(self):
        from declib.api.prototype import parse_prototype
        ret, args = parse_prototype("unsigned long long foo(void)")
        self.assertEqual(ret, "unsigned long long")
        self.assertEqual(args, [])

    def test_parse_bad_raises(self):
        from declib.api.prototype import parse_prototype
        for bad in ["int main", "no parens here", "(int a)"]:
            with self.assertRaises(ValueError):
                parse_prototype(bad)

    def test_format_roundtrip(self):
        from declib.api.prototype import format_prototype
        from declib.artifacts import FunctionHeader, FunctionArgument
        h = FunctionHeader(name="f", addr=0x1000, type_="int",
                           args={0: FunctionArgument(0, "a", "int", 4),
                                 1: FunctionArgument(1, "b", "char *", 8)})
        self.assertEqual(format_prototype(h), "int f(int a, char *b)")


class TestArtifactWireSerialization(unittest.TestCase):
    """The client↔server wire format must survive tricky decompilation text.

    Regression for the Ghidra `Reserved escape sequence used` failure: the
    `toml` encoder mangles literal `\\x01` escapes that show up in C char
    literals. The server now emits JSON on the wire; JSON is stricter about
    backslash escaping, so this test locks that behavior in.
    """

    def test_decompilation_with_backslash_x_roundtrip_json(self):
        from declib.artifacts import Decompilation
        from declib.artifacts.formatting import ArtifactFormat

        # Exactly the kind of text Ghidra emits when decompiling code that
        # compares a byte to a control character: `if (c == '\x01')`.
        text = "if (c == '\\x01') { return 42; }"
        dec = Decompilation(addr=0x1000, text=text, decompiler="ghidra")

        encoded = dec.dumps(fmt=ArtifactFormat.JSON)
        decoded = Decompilation.loads(encoded, fmt=ArtifactFormat.JSON)
        self.assertEqual(decoded.text, text)
        self.assertEqual(decoded.addr, 0x1000)

    def test_decompilation_toml_still_fails_on_backslash_x(self):
        """Document WHY we moved off TOML — if this ever starts working we
        can reconsider, but in the meantime it's load-bearing for the fix."""
        from declib.artifacts import Decompilation
        from declib.artifacts.formatting import ArtifactFormat
        import toml

        text = "if (c == '\\x01') { return 42; }"
        dec = Decompilation(addr=0x1000, text=text, decompiler="ghidra")
        encoded = dec.dumps(fmt=ArtifactFormat.TOML)
        with self.assertRaises(toml.decoder.TomlDecodeError):
            Decompilation.loads(encoded, fmt=ArtifactFormat.TOML)


class TestCLIBatch(unittest.TestCase):
    def _run_batch(self, operations, *extra_args):
        from declib.artifacts import Decompilation
        from declib.cli import decompiler_cli

        client = mock.MagicMock()
        client.__enter__.return_value = client
        client.functions = {0x1000: SimpleNamespace(name="main", size=32)}
        client.decompile.return_value = Decompilation(
            addr=0x1000,
            text="int main(void) { return 0; }",
            decompiler="test",
        )
        client.read_memory.return_value = b"\x7fELF"

        with tempfile.TemporaryDirectory() as tmpdir:
            batch_path = Path(tmpdir) / "operations.jsonl"
            batch_path.write_text(
                "\n".join(
                    value if isinstance(value, str) else json.dumps(value)
                    for value in operations
                )
            )
            args = decompiler_cli.build_parser().parse_args(
                ["batch", "--file", str(batch_path), "--json", *extra_args]
            )
            stdout = StringIO()
            with mock.patch.object(
                decompiler_cli, "_select_server", return_value={"socket_path": "/tmp/test.sock"}
            ) as select_server:
                with mock.patch.object(
                    decompiler_cli, "_connect_client", return_value=client
                ) as connect_client:
                    with redirect_stdout(stdout):
                        exit_code = decompiler_cli.cmd_batch(args)

        return (
            exit_code,
            json.loads(stdout.getvalue()),
            client,
            select_server,
            connect_client,
        )

    def test_mixed_operations_share_one_client(self):
        exit_code, payload, client, select_server, connect_client = self._run_batch(
            [
                {"id": "functions", "argv": ["list_functions", "--filter", "main"]},
                {"id": "decompile", "argv": ["decompile", "main"]},
                {"id": "header", "argv": ["read_memory", "0x1000", "4"]},
            ]
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["summary"]["completed"], 3)
        self.assertEqual(payload["summary"]["failed"], 0)
        self.assertTrue(all(result["ok"] for result in payload["results"]))
        self.assertEqual(payload["results"][0]["result"][0]["name"], "main")
        self.assertEqual(payload["results"][1]["result"]["text"], client.decompile.return_value.text)
        self.assertEqual(payload["results"][2]["result"]["hex"], "7f454c46")
        select_server.assert_called_once()
        connect_client.assert_called_once()
        client.decompile.assert_called_once_with(0x1000, map_lines=False)

    def test_stop_on_error_and_input_errors(self):
        exit_code, payload, _client, _select, _connect = self._run_batch(
            [
                "not json",
                {"id": "never-runs", "argv": ["list_functions"]},
            ],
            "--stop-on-error",
        )

        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["summary"]["requested"], 2)
        self.assertEqual(payload["summary"]["completed"], 1)
        self.assertTrue(payload["summary"]["stopped_early"])
        self.assertIn("Invalid JSON", payload["results"][0]["error"])

    def test_lifecycle_and_raw_operations_are_rejected(self):
        exit_code, payload, _client, _select, _connect = self._run_batch(
            [
                {"id": "stop", "argv": ["stop", "--all"]},
                {"id": "raw", "argv": ["decompile", "main", "--raw"]},
                {"id": "bypass", "argv": ["-v", "stop", "--all"]},
            ]
        )

        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["summary"]["failed"], 3)
        self.assertIn("not allowed", payload["results"][0]["error"])
        self.assertIn("--raw", payload["results"][1]["error"])
        self.assertIn("not allowed", payload["results"][2]["error"])


class TestCLIFormatters(unittest.TestCase):
    """Sanity tests for the small pure-Python helpers in the CLI."""

    def test_format_addr_hex_handles_negative(self):
        """Regression for Ghidra surfacing negative-signed-long section addrs."""
        from declib.cli.decompiler_cli import _format_addr_hex

        # Positive values render as-is.
        self.assertEqual(_format_addr_hex(0x400), "0x400")
        # Negative values wrap to unsigned 64-bit, never emit '0x-...'.
        rendered = _format_addr_hex(-0x100000)
        self.assertTrue(rendered.startswith("0x"))
        self.assertNotIn("-", rendered)
        self.assertEqual(rendered, f"0x{((-0x100000) & ((1 << 64) - 1)):x}")

    def test_annotate_addrs_uses_safe_hex(self):
        from declib.cli.decompiler_cli import _annotate_addrs

        payload = {"addr": -0x100000, "target_addr": 0x1000}
        annotated = _annotate_addrs(payload)
        self.assertNotIn("-", annotated["addr_hex"])
        self.assertEqual(annotated["target_addr_hex"], "0x1000")

    def test_format_line_map_is_stable_and_json_friendly(self):
        from declib.cli.decompiler_cli import _format_line_map

        formatted = _format_line_map({4: {0x1020, 0x1010}, 1: [0x1000]})
        self.assertEqual(
            formatted,
            [
                {"line": 1, "addrs": [0x1000], "addrs_hex": ["0x1000"]},
                {
                    "line": 4,
                    "addrs": [0x1010, 0x1020],
                    "addrs_hex": ["0x1010", "0x1020"],
                },
            ],
        )
        json.dumps(formatted)

    def test_map_lines_requires_json(self):
        result = _run_cli("decompile", "main", "--map-lines", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--map-lines requires --json", result.stderr)

    def test_decompile_requests_and_emits_line_map(self):
        from declib.artifacts import Decompilation
        from declib.cli import decompiler_cli

        client = mock.MagicMock()
        client.functions = {0x1000: SimpleNamespace(name="main")}
        client.decompile.return_value = Decompilation(
            addr=0x1000,
            text="int main(void) { return 0; }",
            line_map={2: {0x1010, 0x1008}},
            decompiler="test",
        )
        client_context = mock.MagicMock()
        client_context.__enter__.return_value = client
        args = decompiler_cli.build_parser().parse_args(
            ["decompile", "main", "--map-lines", "--json"]
        )

        output = StringIO()
        with mock.patch.object(decompiler_cli, "_with_client", return_value=client_context):
            with redirect_stdout(output):
                result = decompiler_cli.cmd_decompile(args)

        self.assertEqual(result, 0)
        client.decompile.assert_called_once_with(0x1000, map_lines=True)
        payload = json.loads(output.getvalue())
        self.assertEqual(
            payload["line_map"],
            [{"line": 2, "addrs": [0x1008, 0x1010], "addrs_hex": ["0x1008", "0x1010"]}],
        )

    def test_parse_and_shape_line_ranges(self):
        from declib.cli.decompiler_cli import (
            _parse_line_range_specs,
            _shape_decompilation_text,
        )

        ranges = _parse_line_range_specs(["2:3", "5:"])
        shaped = _shape_decompilation_text(
            "one\ntwo\nthree\nfour\nfive\n",
            line_ranges=ranges,
        )
        self.assertEqual(shaped["text"], "two\nthree\nfive\n")
        self.assertEqual(
            shaped["source_ranges"],
            [{"start": 2, "end": 3}, {"start": 5, "end": 5}],
        )
        self.assertEqual(shaped["total_lines"], 5)
        self.assertTrue(shaped["bounded"])
        self.assertFalse(shaped["truncated"])

    def test_shape_grep_context_and_character_limit(self):
        from declib.cli.decompiler_cli import (
            _compile_grep_patterns,
            _shape_decompilation_text,
        )

        patterns = _compile_grep_patterns(["firmware", "ADMIN"], ignore_case=True)
        shaped = _shape_decompilation_text(
            "zero\none\nfirmware check\nthree\nadmin path\nfive\n",
            grep_patterns=patterns,
            context=1,
            max_chars=24,
        )
        self.assertEqual(shaped["matched_lines"], [3, 5])
        self.assertEqual(shaped["source_ranges"], [{"start": 2, "end": 4}])
        self.assertEqual(shaped["text"], "one\nfirmware check\nthree")
        self.assertTrue(shaped["truncated"])
        self.assertEqual(shaped["output_chars"], 24)

    def test_invalid_line_ranges_fail_before_decompilation(self):
        from declib.cli.decompiler_cli import _parse_line_range_specs

        for spec in ("", ":", "0:4", "5:2", "abc"):
            with self.subTest(spec=spec):
                with self.assertRaises(SystemExit):
                    _parse_line_range_specs([spec])

    def test_decompile_output_file_omits_text_and_decompiles_once(self):
        from declib.artifacts import Decompilation
        from declib.cli import decompiler_cli

        client = mock.MagicMock()
        client.functions = {0x1000: SimpleNamespace(name="main")}
        client.decompile.return_value = Decompilation(
            addr=0x1000,
            text="int main(void) {\n  return 0;\n}\n",
            decompiler="test",
        )
        client_context = mock.MagicMock()
        client_context.__enter__.return_value = client

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "main.c"
            args = decompiler_cli.build_parser().parse_args(
                [
                    "decompile",
                    "main",
                    "--grep",
                    "return",
                    "--context",
                    "1",
                    "--output",
                    str(output_path),
                    "--json",
                ]
            )
            stdout = StringIO()
            with mock.patch.object(
                decompiler_cli, "_with_client", return_value=client_context
            ):
                with redirect_stdout(stdout):
                    result = decompiler_cli.cmd_decompile(args)

            payload = json.loads(stdout.getvalue())
            self.assertEqual(output_path.read_text(), "int main(void) {\n  return 0;\n}\n")

        self.assertEqual(result, 0)
        client.decompile.assert_called_once_with(0x1000, map_lines=False)
        self.assertNotIn("text", payload)
        self.assertEqual(payload["output"]["path"], str(output_path.resolve()))
        self.assertEqual(payload["output"]["bytes"], 31)
        self.assertEqual(payload["matched_lines"], [2])

    def test_format_line_map_can_filter_selected_source_lines(self):
        from declib.cli.decompiler_cli import _format_line_map

        formatted = _format_line_map(
            {1: {0x1000}, 2: {0x1010}, 3: {0x1020}},
            selected_lines={2, 3},
        )
        self.assertEqual([entry["line"] for entry in formatted], [2, 3])

    def test_existing_output_fails_before_connecting_to_backend(self):
        from declib.cli import decompiler_cli

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "existing.c"
            output_path.write_text("keep me")
            args = decompiler_cli.build_parser().parse_args(
                ["decompile", "main", "--output", str(output_path), "--json"]
            )
            with mock.patch.object(decompiler_cli, "_with_client") as connect:
                with self.assertRaises(SystemExit):
                    decompiler_cli.cmd_decompile(args)

            connect.assert_not_called()
            self.assertEqual(output_path.read_text(), "keep me")

    def test_wait_for_server_reports_early_child_exit_and_log(self):
        from declib.cli import decompiler_cli

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "server.log"
            log_path.write_text("backend import failed\ntraceback details\n")
            process = mock.Mock()
            process.poll.return_value = 17

            with mock.patch.object(
                decompiler_cli.server_registry, "find_server", return_value=None
            ):
                with self.assertRaises(SystemExit) as raised:
                    decompiler_cli._wait_for_server(
                        "deadbeef",
                        process=process,
                        log_path=log_path,
                        timeout=300,
                    )

        message = str(raised.exception)
        self.assertIn("exited with status 17", message)
        self.assertIn(str(log_path), message)
        self.assertIn("backend import failed", message)

    def test_wait_for_server_timeout_includes_bounded_log_tail(self):
        from declib.cli import decompiler_cli

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "server.log"
            log_path.write_text("discard-me\n" + "x" * 32 + "useful tail\n")
            tail = decompiler_cli._read_server_log_tail(log_path, max_bytes=16)
            self.assertNotIn("discard-me", tail)
            self.assertTrue(tail.endswith("useful tail"))

            with self.assertRaises(SystemExit) as raised:
                decompiler_cli._wait_for_server(
                    "slowserver",
                    log_path=log_path,
                    timeout=0,
                )

        message = str(raised.exception)
        self.assertIn("Timed out waiting 0s", message)
        self.assertIn("Server log tail", message)

    def test_load_timeout_argument(self):
        from declib.cli.decompiler_cli import build_parser

        args = build_parser().parse_args(["load", "/tmp/example", "--timeout", "12.5"])
        self.assertEqual(args.timeout, 12.5)


# ---------------------------------------------------------------------------
# Skill installer tests
# ---------------------------------------------------------------------------

class TestSkillInstaller(unittest.TestCase):
    """The bundled `decompiler` skill should ship with the package and install cleanly."""

    def test_bundled_skill_present(self):
        from declib import skills

        names = skills.available_skills()
        self.assertIn("decompiler", names)
        skill = skills.skill_path("decompiler") / "SKILL.md"
        content = skill.read_text()
        self.assertIn("name: decompiler", content)
        self.assertIn("decompiler load", content)

    def test_install_skill_via_cli(self):
        with tempfile.TemporaryDirectory() as dest:
            result = _run_cli("install-skill", "--dest", dest, "--json")
            payload = json.loads(result.stdout)
            self.assertEqual(len(payload["installed"]), 1)
            installed_path = Path(payload["installed"][0]["path"])
            self.assertEqual(payload["installed"][0]["agent"], "custom")
            self.assertTrue((installed_path / "SKILL.md").is_file())

            # Re-install without --force should fail helpfully.
            again = _run_cli("install-skill", "--dest", dest, "--json", check=False)
            self.assertNotEqual(again.returncode, 0)

            # --force overwrites.
            forced = _run_cli("install-skill", "--dest", dest, "--json", "--force")
            self.assertEqual(len(json.loads(forced.stdout)["installed"]), 1)

    def test_install_skill_text_output_is_parsable(self):
        with tempfile.TemporaryDirectory() as dest:
            result = _run_cli("install-skill", "--dest", dest)
            self.assertNotIn("[{'name'", result.stdout)
            self.assertIn("decompiler", result.stdout)

    def test_install_skill_agent_destinations(self):
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as codex_home:
            result = _run_cli(
                "install-skill",
                "--agent", "all",
                "--json",
                env_overrides={"HOME": home, "CODEX_HOME": codex_home},
            )
            payload = json.loads(result.stdout)
            installed = {entry["agent"]: Path(entry["path"]) for entry in payload["installed"]}
            self.assertEqual(set(installed), {"claude", "codex"})
            self.assertEqual(installed["claude"],
                             (Path(home) / ".claude" / "skills" / "decompiler").resolve())
            self.assertEqual(installed["codex"],
                             (Path(codex_home) / "skills" / "decompiler").resolve())

    def test_install_skill_default_prefers_codex_under_codex(self):
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as codex_home:
            result = _run_cli(
                "install-skill",
                "--json",
                env_overrides={"HOME": home, "CODEX_HOME": codex_home, "CODEX_CI": "1"},
            )
            installed = json.loads(result.stdout)["installed"]
            self.assertEqual(len(installed), 1)
            self.assertEqual(installed[0]["agent"], "codex")

    def test_install_skill_default_falls_back_to_claude(self):
        codex_vars = {
            "CODEX_CI": None, "CODEX_HOME": None, "CODEX_MANAGED_BY_NPM": None,
            "CODEX_SANDBOX": None, "CODEX_SANDBOX_NETWORK_DISABLED": None,
            "CODEX_THREAD_ID": None,
        }
        with tempfile.TemporaryDirectory() as home:
            result = _run_cli(
                "install-skill",
                "--json",
                env_overrides={"HOME": home, **codex_vars},
            )
            installed = json.loads(result.stdout)["installed"]
            self.assertEqual(len(installed), 1)
            self.assertEqual(installed[0]["agent"], "claude")

    def test_install_skill_dest_and_agent_are_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as dest:
            result = _run_cli("install-skill", "--dest", dest, "--agent", "codex",
                              check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--dest cannot be combined with --agent",
                          result.stdout + result.stderr)


# ---------------------------------------------------------------------------
# Direct library-level tests (don't need the CLI + subprocess machinery)
# ---------------------------------------------------------------------------

@unittest.skipUnless(FAUXWARE_PATH.exists(), f"Missing test binary: {FAUXWARE_PATH}")
class TestNewDecLibFeatures(unittest.TestCase):
    """Direct tests for list_strings, get_callers, disassemble, xref_from, xref_to_addr."""

    @classmethod
    def setUpClass(cls):
        cls.deci = DecompilerInterface.discover(
            force_decompiler="angr",
            headless=True,
            binary_path=str(FAUXWARE_PATH),
        )

    def test_list_strings(self):
        strings = self.deci.list_strings()
        self.assertGreater(len(strings), 0)

        welcome = self.deci.list_strings(filter=r"Welcome")
        self.assertEqual(len(welcome), 1)
        self.assertIn("Welcome", welcome[0][1])
        self.assertEqual(self.deci.list_strings(filter=r"zzz_no_match"), [])

    def test_disassemble(self):
        addrs = [a for a, f in self.deci.functions.items() if f.name == "main"]
        text = self.deci.disassemble(addrs[0])
        self.assertTrue(any(mnem in text for mnem in ("push", "mov", "call")))

    def test_get_callers_by_addr_name_and_function(self):
        addrs_by_name = {f.name: a for a, f in self.deci.functions.items()}
        auth_addr = addrs_by_name["authenticate"]

        by_addr = self.deci.get_callers(auth_addr)
        by_name = self.deci.get_callers("authenticate")
        self.assertEqual({f.addr for f in by_addr}, {f.addr for f in by_name})
        with self.assertRaises(ValueError):
            self.deci.get_callers("no_such_function_xyz")

    def test_xrefs_from_returns_callees(self):
        """xrefs_from(main) should include authenticate, puts, read, etc."""
        addrs_by_name = {f.name: a for a, f in self.deci.functions.items()}
        main_addr = addrs_by_name["main"]
        callees = self.deci.xrefs_from(main_addr)
        callee_names = {c.name for c in callees if c.name}
        self.assertTrue(
            callee_names & {"authenticate", "puts", "read", "accepted", "rejected"},
            f"expected a known callee in {callee_names}"
        )

    def test_xrefs_to_addr_on_string(self):
        """xrefs_to_addr on the SOSNEAKY constant should point at authenticate."""
        strings = self.deci.list_strings(filter=r"SOSNEAKY")
        self.assertTrue(strings, "SOSNEAKY not found in angr strings")
        str_addr = strings[0][0]
        refs = self.deci.xrefs_to_addr(str_addr)
        ref_names = {getattr(r, "name", None) for r in refs}
        self.assertIn("authenticate", ref_names,
                      f"expected 'authenticate' in xrefs_to_addr(SOSNEAKY): {ref_names}")

    def test_read_memory(self):
        """read_memory should return the ELF magic at the binary's base."""
        # ELF magic at lifted addr 0
        elf = self.deci.read_memory(0, 4)
        self.assertEqual(elf, b"\x7fELF")

        # Welcome string — find via list_strings, then read its bytes.
        strings = self.deci.list_strings(filter=r"Welcome")
        self.assertTrue(strings, "Welcome string not found")
        welcome_addr = strings[0][0]
        bytes_ = self.deci.read_memory(welcome_addr, 7)
        self.assertEqual(bytes_, b"Welcome")

        # Out-of-range read should return None.
        self.assertIsNone(self.deci.read_memory(0xdeadbeef00, 16))

        # Zero/negative size short-circuit.
        self.assertEqual(self.deci.read_memory(0, 0), b"")
        self.assertEqual(self.deci.read_memory(0, -5), b"")


if __name__ == "__main__":
    unittest.main()
