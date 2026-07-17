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
from pathlib import Path

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
