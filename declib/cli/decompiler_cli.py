"""
The `decompiler` CLI: a simplified, LLM-friendly interface to declib.

The CLI is a client that connects to a DecompilerServer. The first `load` of
a binary auto-starts a headless server in the background; subsequent CLI
invocations (including `load`s of other binaries) connect to the right server
via the shared server registry (see declib.api.server_registry).

Subcommands implemented:
- load            start a server on a binary
- list            list running servers
- stop            stop one or all servers (with --save/--discard)
- save            persist backend analysis to disk (durable artifacts)
- list_functions  list functions in the binary, optionally filtered by regex
- decompile       decompile a function by name or address
- disassemble     disassemble a function by name or address
- xref_to         data + code references to a target
- xref_from       things a function calls (callees)
- comment         get/set/append/delete/list comments (annotations)
- global          list/get/rename/retype global variables
- signature       get/set a function's full signature (prototype)
- rename          rename a function or local variable
- create-type     define a new struct/enum/typedef from a C string
- retype          change the type of a function's variable or argument
- sync            copy work on a function from one server into another
- list_strings    list strings in the binary, optionally filtered by regex
- get_callers     functions (call sites only) that call a target
- read            typed reads: int/string/struct at an address
- read_memory     read raw bytes from the binary at an address
- install-skill   install the bundled Agent Skill so LLMs learn the CLI
"""
import argparse
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Standardized exit codes — keep these consistent across subcommands so that
# `&&` chaining and scripts have predictable behavior.
EXIT_OK = 0
EXIT_USER_ERROR = 1        # user asked for something that didn't happen
EXIT_NOT_FOUND = 1         # missing function/name/binary
EXIT_RUNTIME_ERROR = 1     # unhandled/unknown failure
EXIT_UNSUPPORTED = 2       # feature not implemented for the selected backend

from declib.api import server_registry
from declib.decompilers import SUPPORTED_DECOMPILERS
from declib import skills

_l = logging.getLogger("declib.cli.decompiler")

_SERVER_START_TIMEOUT = 300.0  # seconds; Ghidra initial analysis can be slow
_SERVER_POLL_INTERVAL = 0.25


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    # Keep declib chatter quiet unless --verbose; otherwise INFO logs clobber the CLI output.
    if not verbose:
        logging.getLogger("declib").setLevel(logging.WARNING)


def _parse_target(target: str) -> Tuple[Optional[int], Optional[str]]:
    """Parse a user-supplied target into (addr, name).

    Accepts hex (0x...), decimal, or a symbol name. Returns (addr, None) if numeric,
    otherwise (None, target).
    """
    if target is None:
        return None, None
    t = target.strip()
    if t.lower().startswith("0x"):
        try:
            return int(t, 16), None
        except ValueError:
            pass
    if t.isdigit():
        try:
            return int(t, 10), None
        except ValueError:
            pass
    return None, t


def _resolve_function_addr(client, target: str) -> Optional[int]:
    """Resolve a function reference to its address using a client.

    Names are resolved by scanning light artifacts. Addresses may be given in either
    lifted (relative to base) or lowered (absolute/loaded) form; we match whichever
    the server's artifact dict uses.
    """
    addr, name = _parse_target(target)
    if name is not None:
        for _addr, func in client.functions.items():
            if func.name == name:
                return _addr
        return None
    if addr is None:
        return None

    # Addresses may be given as absolute; the server exposes lifted addresses.
    known = set(client.functions.keys())
    if addr in known:
        return addr
    try:
        base = client.binary_base_addr
    except Exception:
        base = 0
    if base and addr >= base and (addr - base) in known:
        return addr - base
    if base and (addr + base) in known:
        return addr + base
    return addr  # let the caller raise if it's truly invalid


def _to_lifted_addr(client, addr: int) -> int:
    """Best-effort: normalize an absolute address into the server's lifted form.

    The server keys artifacts (comments, patches, ...) by lifted address —
    relative to the image base. Users routinely paste absolute addresses, so
    when the value is clearly absolute (>= base and not already a known lifted
    function start) we subtract the base to land it where they expect.
    """
    try:
        if addr in set(client.functions.keys()):
            return addr
    except Exception:
        pass
    try:
        base = client.binary_base_addr
    except Exception:
        base = 0
    if base and addr >= base:
        return addr - base
    return addr


def _select_server(
    server_id: Optional[str],
    binary_path: Optional[str],
    backend: Optional[str],
) -> Dict:
    """Pick a server record from the registry, or error out with a helpful message."""
    records = server_registry.find_servers(
        binary_path=binary_path,
        backend=backend,
    )
    if server_id:
        records = [r for r in records if r.get("id") == server_id]

    if not records:
        filters = {"id": server_id, "binary_path": binary_path, "backend": backend}
        active = {k: v for k, v in filters.items() if v}
        raise SystemExit(
            "No running decompiler server matches "
            f"{active or '(no filters)'}. Start one with `decompiler load <binary>`."
        )
    if len(records) > 1 and not server_id:
        lines = [
            f"{r['id']}  backend={r.get('backend')}  binary={r.get('binary_path')}"
            for r in records
        ]
        raise SystemExit(
            "Multiple servers match. Specify --id to disambiguate:\n  "
            + "\n  ".join(lines)
        )
    return records[0]


def _connect_client(record: Dict):
    from declib.api.decompiler_client import DecompilerClient

    return DecompilerClient(socket_path=record["socket_path"])


def _with_client(args):
    """Resolve & connect to the selected server, returning the client."""
    record = _select_server(
        server_id=getattr(args, "id", None),
        binary_path=getattr(args, "binary", None),
        backend=getattr(args, "backend", None),
    )
    return _connect_client(record)


# ---------------------------------------------------------------------------
# load
# ---------------------------------------------------------------------------

def _spawn_server(
    binary_path: Path,
    backend: str,
    server_id: str,
    project_dir: Optional[Path] = None,
) -> subprocess.Popen:
    """Start a detached headless server process for the given binary."""
    cmd = [
        sys.executable, "-m", "declib",
        "--server",
        "--decompiler", backend,
        "--headless",
        "--binary-path", str(binary_path),
        "--server-id", server_id,
    ]
    if project_dir is not None:
        cmd.extend(["--project-dir", str(project_dir)])
    env = os.environ.copy()
    # Inherit env so things like GHIDRA_INSTALL_DIR flow through.

    # Fully detach: new session so Ctrl-C in the CLI won't kill the server.
    kwargs = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "stdin": subprocess.DEVNULL,
        "env": env,
        "close_fds": True,
    }
    if os.name == "posix":
        kwargs["start_new_session"] = True
    else:
        kwargs["creationflags"] = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    return subprocess.Popen(cmd, **kwargs)


def _wait_for_server(server_id: str, timeout: float = _SERVER_START_TIMEOUT) -> Dict:
    """Block until a server with `server_id` appears in the registry or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        record = server_registry.find_server(server_id=server_id)
        if record and record.get("socket_path") and os.path.exists(record["socket_path"]):
            return record
        time.sleep(_SERVER_POLL_INTERVAL)
    raise SystemExit(
        f"Timed out waiting {timeout:.0f}s for server {server_id} to start. "
        "Check backend dependencies (e.g. GHIDRA_INSTALL_DIR) and retry."
    )


def cmd_load(args) -> int:
    binary_path = Path(args.binary).expanduser().resolve()
    if not binary_path.exists():
        raise SystemExit(f"Binary not found: {binary_path}")

    backend = args.backend
    if backend not in SUPPORTED_DECOMPILERS:
        raise SystemExit(
            f"Unsupported backend {backend!r}; pick one of: {sorted(SUPPORTED_DECOMPILERS)}"
        )

    # Existing server(s) for this binary+backend.
    existing = server_registry.find_servers(binary_path=str(binary_path), backend=backend)
    if existing and args.replace:
        # --replace: tear the old one(s) down first, then start fresh.
        for record in existing:
            _stop_server_by_record(record)
        existing = []
    if existing and not args.force:
        record = existing[0]
        _emit(args, {
            "status": "already_loaded",
            "id": record["id"],
            "binary_path": record.get("binary_path"),
            "backend": record.get("backend"),
            "socket_path": record.get("socket_path"),
        })
        return 0

    server_id = args.id or server_registry.new_server_id()
    # Default project/database location: a per-binary folder under the user
    # cache dir so analysis artifacts don't pollute the binary's directory.
    # Pass --project-dir "" to disable and let the backend drop files beside
    # the binary (legacy behavior).
    project_dir: Optional[Path]
    if args.project_dir == "":
        project_dir = None
    elif args.project_dir is not None:
        project_dir = Path(args.project_dir).expanduser().resolve()
    else:
        project_dir = _default_project_dir(binary_path, backend)
    _spawn_server(binary_path, backend, server_id, project_dir=project_dir)
    record = _wait_for_server(server_id)
    _emit(args, {
        "status": "started",
        "id": record["id"],
        "binary_path": record.get("binary_path"),
        "backend": record.get("backend"),
        "socket_path": record.get("socket_path"),
        "project_dir": str(project_dir) if project_dir is not None else None,
    })
    return 0


def _default_project_dir(binary_path: Path, backend: str) -> Path:
    """Return a stable per-binary cache dir under the user cache root.

    Keyed by binary name + short hash of the absolute path, so two binaries
    with the same basename don't collide. The directory is created lazily
    by the backend (Ghidra creates `<dir>/<binary>_ghidra/`; IDA writes its
    `.id*` files directly into `<dir>`).
    """
    from platformdirs import user_cache_dir
    import hashlib

    path_hash = hashlib.sha1(str(binary_path).encode()).hexdigest()[:8]
    return Path(user_cache_dir("declib")) / "projects" / f"{binary_path.name}-{path_hash}"


# ---------------------------------------------------------------------------
# list / stop
# ---------------------------------------------------------------------------

def cmd_list(args) -> int:
    records = server_registry.list_servers()
    registry_dir = str(server_registry._registry_dir())  # type: ignore[attr-defined]
    if args.show_registry and not args.json:
        print(registry_dir)
        return 0
    if args.json:
        print(json.dumps({"registry_dir": registry_dir, "servers": records}, indent=2, default=str))
        return 0
    if not records:
        print(f"No running decompiler servers.  (registry: {registry_dir})")
        return 0
    print(f"{'ID':<12} {'BACKEND':<8} {'PID':<8} BINARY")
    for r in records:
        print(f"{r.get('id',''):<12} {str(r.get('backend','')):<8} {str(r.get('pid','')):<8} {r.get('binary_path','')}")
    print(f"\n(registry: {registry_dir})")
    return 0


def _stop_server_by_record(record: Dict, save_mode: Optional[str] = None) -> bool:
    """Shut down the server process backing `record`.

    Asks the server to shut itself down gracefully, falling back to SIGTERM/SIGKILL
    on the PID if the request fails. Returns True if we believe the process is
    gone (or never existed) by the time we return.

    ``save_mode`` controls the final flush to disk before teardown:
    - ``"save"``    — persist analysis (``client.save()``) first.
    - ``"discard"`` — tell the backend not to persist on close.
    - ``None``      — leave the backend's default behavior alone.
    """
    from declib.api.decompiler_client import DecompilerClient

    server_id = record.get("id")
    pid = record.get("pid")
    socket_path = record.get("socket_path")
    graceful = False
    try:
        client = DecompilerClient(socket_path=socket_path)
    except Exception as exc:
        _l.warning("Could not connect to server %s: %s", server_id, exc)
        client = None
    if client is not None:
        if save_mode == "save":
            try:
                client.save()
            except NotImplementedError:
                _l.debug("Backend %s does not support saving; nothing to flush.", server_id)
            except Exception as exc:
                _l.warning("save before stop failed for %s: %s", server_id, exc)
        elif save_mode == "discard":
            try:
                client.set_persist_on_close(False)
            except Exception as exc:
                _l.debug("set_persist_on_close(False) failed for %s: %s", server_id, exc)
        try:
            client._send_request({"type": "shutdown_server"})
            graceful = True
        except Exception as exc:
            _l.debug("shutdown_server rejected by %s: %s", server_id, exc)
        client.shutdown()

    if not _wait_for_process_exit(pid, timeout=3.0):
        # Graceful request didn't land or server is stuck — escalate.
        _signal_process(pid, signal.SIGTERM)
        if not _wait_for_process_exit(pid, timeout=2.0):
            _signal_process(pid, signal.SIGKILL)
            _wait_for_process_exit(pid, timeout=1.0)

    server_registry.unregister_server(server_id)
    return graceful or not _process_alive(pid)


def _process_alive(pid) -> bool:
    if not pid:
        return False
    try:
        import psutil

        return psutil.pid_exists(int(pid))
    except Exception:
        return False


def _signal_process(pid, sig) -> None:
    if not pid:
        return
    try:
        os.kill(int(pid), sig)
    except ProcessLookupError:
        return
    except Exception as exc:
        _l.debug("Signal %s to pid %s failed: %s", sig, pid, exc)


def _wait_for_process_exit(pid, timeout: float) -> bool:
    if not pid:
        return True
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _process_alive(pid):
            return True
        time.sleep(0.05)
    return not _process_alive(pid)


def cmd_stop(args) -> int:
    if args.save and args.discard:
        raise SystemExit("decompiler stop: --save and --discard are mutually exclusive")
    records = server_registry.list_servers()
    if args.all:
        targets = records
    elif args.id:
        targets = [r for r in records if r.get("id") == args.id]
    elif args.binary:
        targets = server_registry.find_servers(binary_path=args.binary)
    else:
        raise SystemExit("decompiler stop needs --id, --binary, or --all")

    if not targets:
        raise SystemExit("No matching server to stop")

    save_mode = "save" if args.save else "discard" if args.discard else None

    results = []
    for record in targets:
        ok = _stop_server_by_record(record, save_mode=save_mode)
        results.append({"id": record.get("id"), "stopped": bool(ok), "save_mode": save_mode})
    _emit(args, {"stopped": results})
    return 0


def cmd_save(args) -> int:
    """Persist the selected server's analysis to its on-disk database/project."""
    with _with_client(args) as client:
        try:
            ok = bool(client.save(args.path))
        except NotImplementedError as exc:
            # Re-raise so main() renders the friendly "not implemented" message
            # and returns EXIT_UNSUPPORTED.
            raise NotImplementedError(
                str(exc) or "this backend has no persistent database to save "
                "(e.g. angr is purely in-memory)."
            )
        _emit(args, {"saved": ok, "path": args.path})
        return EXIT_OK if ok else EXIT_USER_ERROR


# ---------------------------------------------------------------------------
# decompile / disassemble
# ---------------------------------------------------------------------------

def _known_function_addrs(client) -> set:
    try:
        return set(client.functions.keys())
    except Exception:
        return set()


def cmd_decompile(args) -> int:
    with _with_client(args) as client:
        addr = _resolve_function_addr(client, args.target)
        known = _known_function_addrs(client)
        if addr is None:
            raise SystemExit(f"Function not found: {args.target!r}")
        if known and addr not in known:
            raise SystemExit(
                f"No function starts at 0x{addr:x}. "
                f"Try `decompiler list_functions --filter '{args.target}'` or "
                "pick a function-start address."
            )
        dec = client.decompile(addr)
        if dec is None:
            raise SystemExit(
                f"Decompiler engine returned no result for 0x{addr:x}. "
                "The address is a known function start, but decompilation "
                "failed — this usually means the backend can't handle this "
                "function (unreachable code, ARM/x86 mode mismatch, etc.)."
            )
        text = dec.text if hasattr(dec, "text") else str(dec)
        if getattr(args, "raw", False):
            # --raw: dump just the text body to stdout, regardless of --json.
            print(text)
            return 0
        out = {
            "addr": addr,
            "decompiler": dec.decompiler if hasattr(dec, "decompiler") else None,
            "text": text,
        }
        _emit(args, out, text_field="text")
    return 0


def cmd_disassemble(args) -> int:
    with _with_client(args) as client:
        addr = _resolve_function_addr(client, args.target)
        known = _known_function_addrs(client)
        if addr is None:
            raise SystemExit(f"Function not found: {args.target!r}")
        if known and addr not in known:
            raise SystemExit(
                f"No function starts at 0x{addr:x}. "
                f"Try `decompiler list_functions --filter '{args.target}'` or "
                "pick a function-start address."
            )
        text = client.disassemble(addr)
        if text is None:
            raise SystemExit(
                f"Disassembler returned no instructions for 0x{addr:x} "
                "(likely a function too small to disassemble or a backend bug)."
            )
        if getattr(args, "raw", False):
            print(text)
            return 0
        _emit(args, {"addr": addr, "text": text}, text_field="text")
    return 0


def cmd_list_functions(args) -> int:
    with _with_client(args) as client:
        pattern = re.compile(args.filter) if args.filter else None
        entries: List[Dict] = []
        for addr, func in sorted(client.functions.items(), key=lambda kv: kv[0]):
            name = getattr(func, "name", None) or ""
            if pattern and not pattern.search(name):
                continue
            size = getattr(func, "size", 0) or 0
            entries.append({"addr": addr, "size": int(size), "name": name})

        if args.json:
            _emit_list(args, entries)
        else:
            if not entries:
                print("No functions matched.")
                return 0
            print(f"{'ADDR':<12} {'SIZE':<8} NAME")
            for e in entries:
                print(f"0x{e['addr']:<10x} {e['size']:<8} {e['name']}")
    return 0


# ---------------------------------------------------------------------------
# xrefs
# ---------------------------------------------------------------------------

def _format_xref(artifact) -> Dict:
    """Render any artifact (Function, GlobalVariable, etc.) as a uniform dict.

    Unlike `_format_function`, this keeps the artifact kind so callers can
    tell code refs apart from data refs.
    """
    return {
        "kind": type(artifact).__name__,
        "addr": getattr(artifact, "addr", None),
        "name": getattr(artifact, "name", None),
    }


def cmd_xref_to(args) -> int:
    """All references — code and data — to the target.

    Note: distinct from `get_callers`, which is call-sites only. `xref_to`
    here asks the backend for *every* artifact that points at the target,
    including globals, strings, and non-call code references.

    Resolution order for ``target``:
    1. Function name or address that matches a known function — use the
       function-level xref path (entry-point references).
    2. A raw numeric address or a string literal surfaced by `list_strings`
       — use the raw-address xref path (data refs to strings, globals, etc.).
    """
    from declib.artifacts import Function

    with _with_client(args) as client:
        parsed_addr, parsed_name = _parse_target(args.target)
        func_addr = _resolve_function_addr(client, args.target)
        known = _known_function_addrs(client)
        is_function_target = func_addr is not None and (not known or func_addr in known)

        resolved_addr: Optional[int] = None
        target_kind: str  # "function" | "address" | "string"

        if is_function_target:
            resolved_addr = func_addr
            target_kind = "function"
        elif parsed_addr is not None:
            # Raw address that isn't a function start — try data xrefs.
            resolved_addr = parsed_addr
            target_kind = "address"
        elif parsed_name is not None:
            # Treat as a string literal: find that string and xref its address.
            match = _find_string_addr(client, parsed_name)
            if match is None:
                raise SystemExit(
                    f"Not found: {args.target!r} is not a function, address, "
                    "or known string. Try `decompiler list_strings --filter "
                    f"'{parsed_name}'` to search."
                )
            resolved_addr = match
            target_kind = "string"
        else:
            raise SystemExit(f"Function not found: {args.target!r}")

        xrefs: List = []
        if target_kind == "function":
            func_stub = Function(resolved_addr, 0)
            try:
                xrefs = client.xrefs_to(func_stub, decompile=bool(args.decompile))
            except Exception as exc:
                _l.debug("xrefs_to raised %s; falling back to get_callers", exc)
                xrefs = client.get_callers(resolved_addr)
        else:
            try:
                xrefs = client.xrefs_to_addr(resolved_addr)
            except Exception as exc:
                _l.debug("xrefs_to_addr raised %s; returning empty", exc)
                xrefs = []

        # Enrich Function entries with names from the light artifact cache,
        # since some backends only return (addr, 0) stubs from xrefs_to.
        light_funcs = dict(client.functions.items())
        data: List[Dict] = []
        for x in xrefs:
            entry = _format_xref(x)
            if entry["kind"] == "Function" and not entry.get("name"):
                func = light_funcs.get(entry.get("addr"))
                if func is not None:
                    entry["name"] = getattr(func, "name", None)
            data.append(entry)
        _emit_xrefs(args, resolved_addr, data, direction="to", target_kind=target_kind)
    return 0


def _find_string_addr(client, value: str) -> Optional[int]:
    """Look up the address of a string literal (exact match, then substring)."""
    try:
        strings = client.list_strings() or []
    except Exception:
        return None
    exact = [addr for addr, text in strings if text == value]
    if exact:
        return exact[0]
    contains = [addr for addr, text in strings if value in text]
    if contains:
        return contains[0]
    return None


def cmd_xref_from(args) -> int:
    """Return the callees of a function (what the function calls).

    Implementation:
    1. Use the backend's native per-function callee query (`xrefs_from`).
    2. Fall back to parsing `call 0x…` from disassembly when the backend
       returns nothing.
    """
    with _with_client(args) as client:
        addr = _resolve_function_addr(client, args.target)
        if addr is None:
            raise SystemExit(f"Function not found: {args.target!r}")

        callees: List[Dict] = []
        seen = set()
        try:
            for callee in client.xrefs_from(addr):
                callee_addr = getattr(callee, "addr", None)
                if callee_addr in seen:
                    continue
                seen.add(callee_addr)
                callees.append(_format_xref(callee))
        except Exception as exc:
            _l.debug("xrefs_from failed (%s); falling back to disasm scan.", exc)

        if not callees:
            # Fallback: parse `call 0x...` from disassembly.
            disasm = client.disassemble(addr) or ""
            call_re = re.compile(r"\bcall\b[^0-9]*0x([0-9a-fA-F]+)")
            functions_by_addr = dict(client.functions.items())
            for match in call_re.finditer(disasm):
                try:
                    callee_addr = int(match.group(1), 16)
                except ValueError:
                    continue
                if callee_addr in seen:
                    continue
                seen.add(callee_addr)
                func = functions_by_addr.get(callee_addr)
                callees.append({
                    "kind": "Function",
                    "addr": callee_addr,
                    "name": func.name if func else None,
                })

        # Enrich entries that came back without a name but whose addr is known
        # from the light artifact cache.
        if callees:
            light_funcs = dict(client.functions.items())
            for entry in callees:
                if entry.get("kind") == "Function" and not entry.get("name"):
                    func = light_funcs.get(entry.get("addr"))
                    if func is not None:
                        entry["name"] = getattr(func, "name", None)

        _emit_xrefs(args, addr, callees, direction="from")
    return 0


def _emit_xrefs(
    args,
    addr: int,
    xrefs: List[Dict],
    *,
    direction: str,
    target_kind: Optional[str] = None,
) -> None:
    payload: Dict = {"addr": addr, "direction": direction, "xrefs": xrefs}
    if target_kind is not None:
        payload["target_kind"] = target_kind
    if args.json:
        print(json.dumps(_annotate_addrs(payload), indent=2, default=str))
        return
    if not xrefs:
        print(f"No xrefs {direction} {_format_addr_hex(addr)}")
        return
    for x in xrefs:
        a = x.get("addr")
        n = x.get("name") or ""
        kind = x.get("kind") or ""
        a_str = _format_addr_hex(a) if isinstance(a, int) else "?"
        if kind:
            print(f"{a_str}\t{kind}\t{n}")
        else:
            print(f"{a_str}\t{n}")


# ---------------------------------------------------------------------------
# rename
# ---------------------------------------------------------------------------

def cmd_rename(args) -> int:
    kind = args.kind
    with _with_client(args) as client:
        if kind == "func":
            addr = _resolve_function_addr(client, args.target)
            if addr is None:
                raise SystemExit(f"Function not found: {args.target!r}")
            func = client.functions[addr]
            if not func:
                raise SystemExit(f"Could not load function at 0x{addr:x}")
            func.name = args.new_name
            if func.header is not None:
                func.header.name = args.new_name
            ok = bool(client.set_artifact(func))
            _emit(args, {"kind": "func", "addr": addr, "new_name": args.new_name, "success": ok})
            return EXIT_OK if ok else EXIT_USER_ERROR
        elif kind == "var":
            if not args.function:
                raise SystemExit("--function is required when renaming a variable")
            func_addr = _resolve_function_addr(client, args.function)
            if func_addr is None:
                raise SystemExit(f"Function not found: {args.function!r}")
            func = client.functions[func_addr]
            if not func:
                raise SystemExit(f"Could not load function at 0x{func_addr:x}")
            name_map = {args.target: args.new_name}
            ok = bool(client.rename_local_variables_by_names(func, name_map))
            _emit(args, {"kind": "var", "function_addr": func_addr,
                         "old_name": args.target, "new_name": args.new_name,
                         "success": ok})
            return EXIT_OK if ok else EXIT_USER_ERROR
        raise SystemExit(f"Unknown rename kind: {kind}")


# ---------------------------------------------------------------------------
# comment (get / set / append / delete / list)
# ---------------------------------------------------------------------------

def cmd_comment(args) -> int:
    """CRUD for comments/annotations, keyed by address.

    ``set`` replaces, ``append`` concatenates onto whatever is already there,
    ``get``/``delete`` operate on a single address, and ``list`` enumerates
    every comment the backend knows about (optionally regex-filtered).
    """
    from declib.artifacts import Comment

    action = args.comment_action
    with _with_client(args) as client:
        if action == "list":
            pattern = re.compile(args.filter) if args.filter else None
            entries: List[Dict] = []
            for addr, cmt in sorted(client.comments.items(), key=lambda kv: kv[0]):
                text = getattr(cmt, "comment", None) or ""
                if pattern and not pattern.search(text):
                    continue
                entries.append({
                    "addr": addr,
                    "decompiled": bool(getattr(cmt, "decompiled", False)),
                    "comment": text,
                })
            if args.json:
                _emit_list(args, entries)
            else:
                if not entries:
                    print("No comments.")
                    return EXIT_OK
                for e in entries:
                    print(f"{_format_addr_hex(e['addr'])}\t{e['comment']}")
            return EXIT_OK

        addr_value, _ = _parse_target(args.addr)
        if addr_value is None:
            raise SystemExit(f"Invalid address {args.addr!r}; expected hex (0x..) or decimal.")
        lifted = _to_lifted_addr(client, addr_value)

        if action == "get":
            cmt = client.get_comment(lifted)
            if cmt is None:
                raise SystemExit(f"No comment at {_format_addr_hex(lifted)}")
            _emit(args, {
                "addr": lifted,
                "decompiled": bool(getattr(cmt, "decompiled", False)),
                "comment": cmt.comment,
            }, text_field="comment")
            return EXIT_OK

        if action == "delete":
            ok = bool(client.delete_comment(lifted))
            _emit(args, {"addr": lifted, "deleted": ok})
            return EXIT_OK if ok else EXIT_USER_ERROR

        # set / append
        new_text = args.text
        if action == "append":
            existing = client.get_comment(lifted)
            if existing is not None and existing.comment:
                new_text = f"{existing.comment}\n{new_text}"

        comment = Comment(addr=lifted, comment=new_text, decompiled=bool(args.decompiled))
        ok = bool(client.set_artifact(comment))
        if not ok:
            raise SystemExit(
                f"Backend rejected the comment at {_format_addr_hex(lifted)}. "
                "Some backends (IDA) only accept comments at addresses inside a "
                "function — check the address with `list_functions`/`disassemble`."
            )
        _emit(args, {
            "addr": lifted,
            "decompiled": bool(args.decompiled),
            "comment": new_text,
            "success": ok,
        })
        return EXIT_OK


# ---------------------------------------------------------------------------
# global (list / get / rename / retype)
# ---------------------------------------------------------------------------

def cmd_global(args) -> int:
    """CRUD-lite for global variables, keyed by address."""
    from declib.artifacts import GlobalVariable

    action = args.global_action
    with _with_client(args) as client:
        if action == "list":
            pattern = re.compile(args.filter) if args.filter else None
            entries: List[Dict] = []
            for addr, gv in sorted(client.global_vars.items(), key=lambda kv: kv[0]):
                name = getattr(gv, "name", None) or ""
                if pattern and not pattern.search(name):
                    continue
                entries.append({
                    "addr": addr, "name": name,
                    "type": getattr(gv, "type", None), "size": getattr(gv, "size", None),
                })
            if args.json:
                _emit_list(args, entries)
            else:
                if not entries:
                    print("No global variables.")
                    return EXIT_OK
                print(f"{'ADDR':<12} {'SIZE':<6} {'TYPE':<20} NAME")
                for e in entries:
                    print(f"{_format_addr_hex(e['addr']):<12} {str(e['size'] or ''):<6} "
                          f"{str(e['type'] or ''):<20} {e['name']}")
            return EXIT_OK

        addr_value, _ = _parse_target(args.addr)
        if addr_value is None:
            raise SystemExit(f"Invalid address {args.addr!r}; expected hex (0x..) or decimal.")
        lifted = _to_lifted_addr(client, addr_value)

        if action == "get":
            gv = client.get_global_var(lifted)
            if gv is None:
                raise SystemExit(f"No global variable at {_format_addr_hex(lifted)}")
            _emit(args, {"addr": lifted, "name": gv.name, "type": gv.type, "size": gv.size})
            return EXIT_OK

        # rename / retype: build a partial GlobalVariable and push it through.
        if action == "rename":
            gvar = GlobalVariable(addr=lifted, name=args.new_name)
        else:  # retype
            gvar = GlobalVariable(addr=lifted, type_=args.new_type)
        ok = bool(client.set_artifact(gvar))
        if not ok:
            raise SystemExit(
                f"Backend rejected global {action} at {_format_addr_hex(lifted)} "
                f"(the backend may not support this — e.g. Ghidra global retype is best-effort)."
            )
        refreshed = client.get_global_var(lifted)
        _emit(args, {
            "addr": lifted, "action": action,
            "name": getattr(refreshed, "name", None),
            "type": getattr(refreshed, "type", None),
            "success": ok,
        })
        return EXIT_OK


# ---------------------------------------------------------------------------
# signature (get / set) — full function prototype
# ---------------------------------------------------------------------------

def cmd_signature(args) -> int:
    """Get or set a function's full signature (return type + argument types/names)."""
    from declib.api.prototype import parse_prototype, format_prototype

    action = args.signature_action
    with _with_client(args) as client:
        func_addr = _resolve_function_addr(client, args.function)
        if func_addr is None:
            raise SystemExit(f"Function not found: {args.function!r}")
        known = _known_function_addrs(client)
        if known and func_addr not in known:
            raise SystemExit(f"Function not found: {args.function!r}")

        if action == "get":
            func = client.functions[func_addr]
            if func is None or func.header is None:
                raise SystemExit(f"No signature available for {args.function!r}")
            proto = format_prototype(func.header)
            _emit(args, {
                "function_addr": func_addr,
                "signature": proto,
                "return_type": func.header.type,
                "args": [{"name": a.name, "type": a.type}
                         for _o, a in sorted(func.header.args.items())],
            }, text_field="signature")
            return EXIT_OK

        # set: validate the prototype client-side for a clean error, then let
        # the backend apply it (IDA uses SetType; others use the header path).
        try:
            parse_prototype(args.prototype)
        except ValueError as exc:
            raise SystemExit(f"Could not parse prototype: {exc}")

        ok = bool(client.set_function_signature(func_addr, args.prototype))
        if not ok:
            raise SystemExit(f"Backend rejected the signature for {args.function!r}.")

        refreshed = client.functions[func_addr]
        _emit(args, {
            "function_addr": func_addr,
            "applied_signature": format_prototype(refreshed.header)
            if refreshed is not None and refreshed.header else None,
            "success": ok,
        })
        return EXIT_OK


# ---------------------------------------------------------------------------
# create-type / retype
# ---------------------------------------------------------------------------

def cmd_create_type(args) -> int:
    """Define a new struct/enum/typedef from a C string and apply it.

    The definition is parsed (client-side, decompiler-free) into a declib
    artifact and pushed through the normal type-setting path, which works
    across every backend.
    """
    from declib.api.type_definition_parser import (
        parse_type_definition, TypeDefinitionParseError,
    )

    try:
        artifact = parse_type_definition(args.definition)
    except TypeDefinitionParseError as exc:
        # Fail before connecting — nothing about a server changes the parse.
        raise SystemExit(f"Could not parse type definition: {exc}")

    with _with_client(args) as client:
        ok = bool(client.set_artifact(artifact))
        _emit(args, {
            "kind": type(artifact).__name__,
            "name": artifact.name,
            "size": getattr(artifact, "size", None),
            "members": len(artifact.members) if hasattr(artifact, "members") else None,
            "success": ok,
        })
    return EXIT_OK if ok else EXIT_USER_ERROR


def _find_variable(func, var_name: str):
    """Locate a variable by name in a function. Returns (kind, var) or (None, None).

    Stack variables are checked before arguments. ``kind`` is "stack" or "arg".
    """
    for svar in func.stack_vars.values():
        if svar.name == var_name:
            return "stack", svar
    if func.header is not None:
        for arg in func.header.args.values():
            if arg.name == var_name:
                return "arg", arg
    return None, None


def _compute_type_size(client, type_str: str) -> int:
    """Best-effort byte size for a (possibly user-defined) type string."""
    ctype = client.type_parser.parse_type(type_str)
    if ctype is not None and ctype.size:
        return ctype.size
    # Unknown/user-defined non-pointer type (e.g. a struct by value): ask the
    # backend what it already knows about this type.
    try:
        defined = client.get_defined_type(type_str)
    except Exception:
        defined = None
    size = getattr(defined, "size", None)
    if size:
        return size
    # 0 means "let the backend infer the size".
    return ctype.size if ctype is not None else 0


def cmd_retype(args) -> int:
    """Change the type of a local variable or argument of a function."""
    with _with_client(args) as client:
        func_addr = _resolve_function_addr(client, args.function)
        if func_addr is None:
            raise SystemExit(f"Function not found: {args.function!r}")
        func = client.functions[func_addr]
        if not func:
            raise SystemExit(f"Could not load function at 0x{func_addr:x}")

        kind, var = _find_variable(func, args.variable)
        if var is None:
            raise SystemExit(
                f"Variable {args.variable!r} not found in {args.function!r}. "
                "Check the name (it is case-sensitive)."
            )

        var.type = args.new_type
        var.size = _compute_type_size(client, args.new_type)

        ok = bool(client.set_artifact(func))
        if not ok:
            raise SystemExit(
                f"Backend rejected retype of {args.variable!r} to {args.new_type!r}."
            )

        # Re-read so the caller can see what the backend actually stored.
        refreshed = client.functions[func_addr]
        _, new_var = _find_variable(refreshed, args.variable)
        _emit(args, {
            "function_addr": func_addr,
            "variable": args.variable,
            "kind": kind,
            "new_type": args.new_type,
            "applied_type": getattr(new_var, "type", None) if new_var else None,
            "success": ok,
        })
    return EXIT_OK


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------

def cmd_sync(args) -> int:
    """Copy work on a function from one running server into another.

    Source is selected by --from-id; destination by the usual
    --id/--binary/--backend. Syncs the function's referenced user types
    (struct/enum/typedef) first, then the function header (name/return/args)
    and stack variables. Addresses and stack offsets are canonical in lifted
    form, so they re-key correctly on the destination even if it names the
    function differently.
    """
    from declib.artifacts import Struct, Enum, Typedef

    src_record = _select_server(server_id=args.from_id, binary_path=None, backend=None)
    dst_record = _select_server(
        server_id=getattr(args, "id", None),
        binary_path=getattr(args, "binary", None),
        backend=getattr(args, "backend", None),
    )
    if src_record.get("id") == dst_record.get("id"):
        raise SystemExit(
            f"Source and destination are the same server (id={src_record.get('id')}). "
            "Pick two different servers."
        )

    src = _connect_client(src_record)
    dst = None
    try:
        dst = _connect_client(dst_record)

        addr = _resolve_function_addr(src, args.target)
        known = _known_function_addrs(src)
        if addr is None or (known and addr not in known):
            raise SystemExit(f"Function not found on source: {args.target!r}")

        src_func = src.functions[addr]
        if not src_func:
            raise SystemExit(f"Could not load function at 0x{addr:x} on source")

        # 1) Sync referenced user types first so retypes resolve on the dest.
        synced_types, failed_types = [], []
        try:
            deps = src.get_dependencies(src_func, decompile=True)
        except Exception as exc:
            _l.debug("get_dependencies failed: %s", exc)
            deps = []
        for dep in deps:
            if isinstance(dep, (Struct, Enum, Typedef)):
                name = getattr(dep, "name", None)
                try:
                    ok_dep = bool(dst.set_artifact(dep))
                except Exception as exc:
                    _l.debug("type sync failed for %s: %s", name, exc)
                    ok_dep = False
                (synced_types if ok_dep else failed_types).append(name)

        # 2) Sync the function header + stack vars in one shot.
        func_ok = bool(dst.set_artifact(src_func))

        synced_vars = sorted(
            (sv.offset, getattr(sv, "name", None))
            for sv in (src_func.stack_vars or {}).values()
        )
        _emit(args, {
            "target": args.target,
            "addr": addr,
            "from_id": src_record.get("id"),
            "to_id": dst_record.get("id"),
            "function_name": src_func.name,
            "synced_types": synced_types,
            "failed_types": failed_types,
            "synced_stack_vars": [{"offset": off, "name": nm} for off, nm in synced_vars],
            "success": func_ok,
        })
        return EXIT_OK if func_ok else EXIT_USER_ERROR
    finally:
        src.shutdown()
        if dst is not None:
            dst.shutdown()


# ---------------------------------------------------------------------------
# list_strings / get_callers (new core APIs)
# ---------------------------------------------------------------------------

def cmd_list_strings(args) -> int:
    """List strings the decompiler has identified in the binary.

    This surfaces exactly what the backend's own string detector produced —
    nothing more, nothing less. Decompilers miss things (angr in particular
    is thin on `.rodata`), so if this looks sparse, reach for an external
    tool (`strings(1)`, `rabin2 -z`, `readelf -p .rodata`) to get the
    complete picture.
    """
    with _with_client(args) as client:
        native = client.list_strings(filter=args.filter) or []

        results: List[Dict] = []
        for addr, s in native:
            if len(s) < args.min_length:
                continue
            results.append({"addr": addr, "string": s})

        # Sort by addr.
        results.sort(key=lambda e: e.get("addr", 0))

        if args.json:
            _emit_list(args, results)
        else:
            for entry in results:
                print(f"{_format_addr_hex(entry['addr'])}\t{entry['string']}")
    return 0


def cmd_get_callers(args) -> int:
    """Functions that contain a call to the target (call-sites only).

    Distinct from `xref_to`, which returns every reference (code *or* data).
    If you want the full reference set, use `xref_to` instead.
    """
    with _with_client(args) as client:
        # Reuse the resolver so absolute addresses get normalized to the lifted
        # form the server expects.
        resolved = _resolve_function_addr(client, args.target)
        if resolved is None:
            raise SystemExit(f"Function not found: {args.target!r}")
        try:
            callers = client.get_callers(resolved)
        except ValueError as exc:
            raise SystemExit(str(exc))
        data = [_format_xref(c) for c in callers]
        if args.json:
            _emit(args, {"target": args.target, "target_addr": resolved, "callers": data})
        else:
            if not data:
                print(f"No callers found for {args.target!r}")
            else:
                for entry in data:
                    a = entry.get("addr")
                    n = entry.get("name") or ""
                    print(f"0x{a:x}\t{n}" if a is not None else f"?\t{n}")
    return 0


# ---------------------------------------------------------------------------
# read_memory
# ---------------------------------------------------------------------------

def cmd_read_memory(args) -> int:
    """Read ``size`` bytes from the binary starting at ``addr``.

    Address accepts hex (``0x...``) or decimal. Output defaults to a hex+ascii
    dump; use ``--format hex`` for a single hex blob, ``--format raw`` to write
    raw bytes to stdout, or ``--json`` for a JSON envelope with the bytes
    base64-encoded.
    """
    import base64

    addr_value, name = _parse_target(args.addr)
    if addr_value is None:
        raise SystemExit(
            f"Invalid address {args.addr!r}; expected hex (0x..) or decimal."
        )
    if args.size <= 0:
        raise SystemExit(f"--size must be > 0 (got {args.size})")

    with _with_client(args) as client:
        # Normalize absolute addresses to the server's lifted form so that
        # `0x402320` and the image-relative `0x2320` both land on the same
        # byte instead of the backend double-adding the image base.
        lifted = _to_lifted_addr(client, addr_value)
        data = client.read_memory(lifted, args.size)
        if data is None:
            raise SystemExit(
                f"Backend could not read 0x{args.size:x} bytes at "
                f"{_format_addr_hex(lifted)}. The address may be "
                "uninitialized, unmapped, or outside any loaded segment."
            )
        # Some backends return short reads when the request straddles the
        # end of a mapped region; surface that in the JSON output and warn
        # in text mode so the caller knows.
        actual_size = len(data)

        if args.format == "raw" and not args.json:
            sys.stdout.buffer.write(data)
            return 0

        if args.json:
            payload = {
                "addr": lifted,
                "size": actual_size,
                "requested_size": args.size,
                "bytes_b64": base64.b64encode(data).decode("ascii"),
                "hex": data.hex(),
            }
            print(json.dumps(_annotate_addrs(payload), indent=2, default=str))
            return 0

        if args.format == "hex":
            print(data.hex())
            return 0

        # Default: hexdump-style output.
        for line in _hexdump(data, base_addr=lifted):
            print(line)
        if actual_size < args.size:
            print(
                f"# short read: got {actual_size} of {args.size} requested bytes",
                file=sys.stderr,
            )
    return 0


# ---------------------------------------------------------------------------
# read (typed: int / string / struct)
# ---------------------------------------------------------------------------

def _decode_scalar(type_str: Optional[str], chunk: bytes, endian: str = "little"):
    """Best-effort decode of a struct member's bytes based on its C type."""
    if not chunk:
        return None
    t = (type_str or "").strip()
    if t.endswith("*"):  # pointer
        return _format_addr_hex(int.from_bytes(chunk, endian, signed=False))
    if "char" in t and "[" in t:  # char array -> string
        nul = chunk.find(b"\x00")
        raw = chunk[:nul] if nul != -1 else chunk
        return raw.decode("utf-8", errors="replace")
    if "[" not in t and len(chunk) in (1, 2, 4, 8):  # scalar integer
        return int.from_bytes(chunk, endian, signed=False)
    return None  # unknown/aggregate: caller still has the hex


def cmd_read(args) -> int:
    """Typed reads: decode memory as an integer, C string, or struct."""
    action = args.read_action
    with _with_client(args) as client:
        addr_value, _ = _parse_target(args.addr)
        if addr_value is None:
            raise SystemExit(f"Invalid address {args.addr!r}; expected hex (0x..) or decimal.")
        lifted = _to_lifted_addr(client, addr_value)
        endian = "big" if getattr(args, "endian", "little") == "big" else "little"

        if action == "int":
            size = args.size or (client.default_pointer_size or 8)
            data = client.read_memory(lifted, size)
            if data is None or len(data) < size:
                raise SystemExit(
                    f"Could not read {size} bytes at {_format_addr_hex(lifted)}."
                )
            value = int.from_bytes(data[:size], endian, signed=args.signed)
            _emit(args, {
                "addr": lifted, "size": size, "signed": bool(args.signed),
                "endian": endian, "value": value,
                "hex": "0x" + data[:size].hex(),
            })
            return EXIT_OK

        if action == "string":
            data = client.read_memory(lifted, args.max_len)
            if data is None:
                raise SystemExit(f"Could not read a string at {_format_addr_hex(lifted)}.")
            nul = data.find(b"\x00")
            raw = data[:nul] if nul != -1 else data
            text = raw.decode(args.encoding, errors="replace")
            _emit(args, {
                "addr": lifted, "length": len(raw),
                "truncated": nul == -1 and len(data) >= args.max_len,
                "string": text,
            }, text_field="string")
            return EXIT_OK

        if action == "struct":
            try:
                struct = client.structs[args.name]
            except KeyError:
                raise SystemExit(
                    f"Struct {args.name!r} is not defined. Define it with "
                    f"`create-type` first, or check the name."
                )
            size = struct.size or 0
            if not size and struct.members:
                size = max((off + (m.size or 0)) for off, m in struct.members.items())
            if not size:
                raise SystemExit(f"Struct {args.name!r} has zero size; nothing to read.")
            data = client.read_memory(lifted, size)
            if data is None:
                raise SystemExit(
                    f"Could not read {size} bytes for struct {args.name!r} at "
                    f"{_format_addr_hex(lifted)}."
                )
            members = []
            for off in sorted(struct.members):
                m = struct.members[off]
                msize = m.size or 0
                chunk = data[off:off + msize] if msize else b""
                members.append({
                    "offset": off, "name": m.name, "type": m.type, "size": msize,
                    "hex": chunk.hex(), "value": _decode_scalar(m.type, chunk, endian),
                })
            if args.json:
                _emit(args, {"addr": lifted, "struct": args.name, "size": size, "members": members})
            else:
                print(f"struct {args.name} @ {_format_addr_hex(lifted)} (size {size}):")
                for m in members:
                    val = "" if m["value"] is None else f" = {m['value']}"
                    print(f"  +0x{m['offset']:<4x} {str(m['name'] or ''):<16} "
                          f"{str(m['type'] or ''):<18}{val}  ({m['hex']})")
            return EXIT_OK

        raise SystemExit(f"Unknown read action: {action}")


def _hexdump(data: bytes, *, base_addr: int = 0, width: int = 16) -> List[str]:
    """Return a list of hexdump lines like ``addr: hh hh ... |ascii|``."""
    lines: List[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Pad short final lines so the ASCII column stays aligned.
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{_format_addr_hex(base_addr + offset)}: {hex_part}  |{ascii_part}|")
    return lines


# ---------------------------------------------------------------------------
# install-skill
# ---------------------------------------------------------------------------

_SKILL_AGENT_CHOICES = ("claude", "codex", "all")


def _codex_skill_dest() -> Path:
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return Path(codex_home).expanduser() / "skills"
    return Path(os.path.expanduser("~/.codex/skills"))


def _skill_dest_for_agent(agent: str) -> Path:
    if agent == "claude":
        return Path(os.path.expanduser("~/.claude/skills"))
    if agent == "codex":
        return _codex_skill_dest()
    raise ValueError(f"Unknown skill agent: {agent!r}")


def _default_skill_agents() -> List[str]:
    # Codex sets CODEX_* env vars in its execution environment. Prefer its
    # skill directory there, while preserving Claude as the normal shell default.
    if any(key.startswith("CODEX_") for key in os.environ):
        return ["codex"]
    return ["claude"]


def _selected_skill_agents(raw_agents: Optional[List[str]]) -> List[str]:
    agents = raw_agents or _default_skill_agents()
    if "all" in agents:
        agents = ["claude", "codex"]

    selected: List[str] = []
    for agent in agents:
        if agent not in ("claude", "codex"):
            raise SystemExit(
                f"Unsupported skill agent {agent!r}; pick one of: claude, codex, all"
            )
        if agent not in selected:
            selected.append(agent)
    return selected


def _skill_destinations(args) -> List[Tuple[str, Path]]:
    if args.dest:
        if args.agent:
            raise SystemExit("--dest cannot be combined with --agent")
        return [("custom", Path(args.dest).expanduser().resolve())]

    return [
        (agent, _skill_dest_for_agent(agent).expanduser().resolve())
        for agent in _selected_skill_agents(args.agent)
    ]


def cmd_install_skill(args) -> int:
    names = args.names or skills.available_skills()
    if not names:
        raise SystemExit("No bundled skills to install")

    installed: List[Dict] = []
    for agent, dest_root in _skill_destinations(args):
        dest_root.mkdir(parents=True, exist_ok=True)
        for name in names:
            src = skills.skill_path(name)
            dest = dest_root / name
            if dest.exists() and not args.force:
                raise SystemExit(
                    f"Skill already exists at {dest}. Pass --force to overwrite."
                )
            if dest.exists() and args.force:
                shutil.rmtree(dest)
            shutil.copytree(src, dest)
            installed.append({"name": name, "agent": agent, "path": str(dest)})

    if args.json:
        print(json.dumps({"installed": installed}, indent=2, default=str))
    else:
        for entry in installed:
            agent = "" if entry["agent"] == "custom" else f" ({entry['agent']})"
            print(f"installed {entry['name']}{agent} -> {entry['path']}")
    return 0


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

def _annotate_addrs(payload):
    """Recursively add `*_hex` siblings for every `*addr` integer field.

    JSON historically emitted addresses as decimals; feedback was that this
    is awkward when copying from one command to another. Instead of breaking
    existing int fields, we add a sibling hex-string field so both forms
    are available. A key named `addr` gets `addr_hex`, `target_addr` gets
    `target_addr_hex`, `function_addr` gets `function_addr_hex`, etc.
    """
    if isinstance(payload, dict):
        for key in list(payload.keys()):
            value = payload[key]
            if (
                (key == "addr" or key.endswith("_addr"))
                and isinstance(value, int)
                and f"{key}_hex" not in payload
            ):
                payload[f"{key}_hex"] = _format_addr_hex(value)
        for v in payload.values():
            _annotate_addrs(v)
    elif isinstance(payload, list):
        for item in payload:
            _annotate_addrs(item)
    return payload


def _format_addr_hex(value: int) -> str:
    """Format an address as `0x<hex>`, normalizing negatives to unsigned 64-bit.

    Some backends (Ghidra in particular) can surface java-signed long values
    for synthetic addresses. Emitting `0x-100000` in JSON is useless — render
    those as their unsigned-64 equivalent so downstream consumers always see
    a well-formed hex address.
    """
    if value < 0:
        value &= (1 << 64) - 1
    return f"0x{value:x}"


def _emit(args, payload: Dict, *, text_field: Optional[str] = None) -> None:
    """Emit a response either as JSON or as a human-readable block."""
    if args.json:
        print(json.dumps(_annotate_addrs(payload), indent=2, default=str))
        return
    if text_field and text_field in payload:
        print(payload[text_field])
        return
    # Default: key: value lines
    for k, v in payload.items():
        print(f"{k}: {v}")


def _emit_list(args, payload):
    """Same as _emit but for a top-level list payload (JSON arrays)."""
    if args.json:
        print(json.dumps(_annotate_addrs(payload), indent=2, default=str))
        return
    # Fallback: print each item on its own line as "key: value" pairs if
    # it's a dict; otherwise str(item).
    for item in payload:
        if isinstance(item, dict):
            print(" ".join(f"{k}={v}" for k, v in item.items()))
        else:
            print(item)


def _format_function(func) -> Dict:
    return {
        "addr": getattr(func, "addr", None),
        "name": getattr(func, "name", None),
    }


# ---------------------------------------------------------------------------
# argparse plumbing
# ---------------------------------------------------------------------------

def _add_server_filter_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--id", dest="id", help="Server ID to target (see `decompiler list`).")
    p.add_argument("--binary", dest="binary", help="Match server by binary path.")
    p.add_argument("--backend", dest="backend", choices=sorted(SUPPORTED_DECOMPILERS), help="Match server by backend.")


def _add_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--json", action="store_true", help="Emit JSON output instead of text.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decompiler",
        description=(
            "LLM-friendly decompiler CLI powered by DecLib. "
            "Load a binary once, then run decompile/disassemble/xref/rename "
            "commands. Multiple binaries/backends can run concurrently."
        ),
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # load
    p_load = sub.add_parser("load", help="Load a binary, starting a server if needed.")
    p_load.add_argument("binary", help="Path to the binary to analyze.")
    p_load.add_argument("--backend", default="angr", choices=sorted(SUPPORTED_DECOMPILERS),
                        help="Backend decompiler to use (default: angr).")
    p_load.add_argument("--id", dest="id", help="Explicit server ID (otherwise auto-generated).")
    p_load.add_argument("--force", action="store_true",
                        help="Start a new server even if one already exists for this binary.")
    p_load.add_argument("--replace", action="store_true",
                        help="Stop the existing server for this binary+backend (if any) before starting.")
    p_load.add_argument(
        "--project-dir",
        dest="project_dir",
        help=(
            "Where the backend should store its project/database files "
            "(Ghidra project, IDA .id*, etc.). Default: a per-binary folder "
            "under the user cache dir. Pass '' to drop files next to the binary."
        ),
    )
    _add_output_args(p_load)
    p_load.set_defaults(func=cmd_load)

    # list
    p_list = sub.add_parser("list", help="List running decompiler servers.")
    p_list.add_argument("--show-registry", action="store_true",
                        help="Print just the registry directory path and exit.")
    _add_output_args(p_list)
    p_list.set_defaults(func=cmd_list)

    # list_functions
    p_lf = sub.add_parser("list_functions", help="List functions in the binary.")
    p_lf.add_argument("--filter", dest="filter", help="Regex to filter function names.")
    _add_server_filter_args(p_lf)
    _add_output_args(p_lf)
    p_lf.set_defaults(func=cmd_list_functions)

    # stop
    p_stop = sub.add_parser("stop", help="Stop a running server.")
    p_stop.add_argument("--id", dest="id", help="Server ID to stop.")
    p_stop.add_argument("--binary", dest="binary", help="Stop servers for this binary.")
    p_stop.add_argument("--all", action="store_true", help="Stop every running server.")
    p_stop.add_argument("--save", action="store_true",
                        help="Persist analysis to disk before stopping (durable .i64/.gpr/.bndb).")
    p_stop.add_argument("--discard", action="store_true",
                        help="Explicitly drop unsaved edits on stop (default for IDA; overrides Ghidra's save-on-close).")
    _add_output_args(p_stop)
    p_stop.set_defaults(func=cmd_stop)

    # save
    p_save = sub.add_parser(
        "save",
        help=(
            "Persist the backend's analysis to disk so renames/types/comments "
            "survive a stop + reload. IDA writes its .i64, Ghidra saves the "
            "project, Binary Ninja writes a .bndb; angr (in-memory) is unsupported."
        ),
    )
    p_save.add_argument("--path", dest="path", default=None,
                        help="Explicit output path (backend-dependent; defaults to the open database).")
    _add_server_filter_args(p_save)
    _add_output_args(p_save)
    p_save.set_defaults(func=cmd_save)

    # decompile
    p_dec = sub.add_parser("decompile", help="Decompile a function by name or address.")
    p_dec.add_argument("target", help="Function name or address (hex/decimal).")
    p_dec.add_argument("--raw", action="store_true",
                       help="Print the decompilation text directly (no JSON or header wrapping).")
    _add_server_filter_args(p_dec)
    _add_output_args(p_dec)
    p_dec.set_defaults(func=cmd_decompile)

    # disassemble
    p_dis = sub.add_parser("disassemble", help="Disassemble a function by name or address.")
    p_dis.add_argument("target", help="Function name or address (hex/decimal).")
    p_dis.add_argument("--raw", action="store_true",
                       help="Print the disassembly text directly (no JSON or header wrapping).")
    _add_server_filter_args(p_dis)
    _add_output_args(p_dis)
    p_dis.set_defaults(func=cmd_disassemble)

    # xref_to
    p_xto = sub.add_parser(
        "xref_to",
        help=(
            "Every reference (code AND data) to a target. "
            "For call-sites only, see `get_callers`."
        ),
    )
    p_xto.add_argument("target", help="Function name or address (hex/decimal).")
    p_xto.add_argument("--decompile", action="store_true",
                       help="Ask the backend to decompile first (picks up more refs on Ghidra).")
    _add_server_filter_args(p_xto)
    _add_output_args(p_xto)
    p_xto.set_defaults(func=cmd_xref_to)

    # xref_from
    p_xfrom = sub.add_parser("xref_from", help="Things a function calls (callees).")
    p_xfrom.add_argument("target", help="Function name or address (hex/decimal).")
    _add_server_filter_args(p_xfrom)
    _add_output_args(p_xfrom)
    p_xfrom.set_defaults(func=cmd_xref_from)

    # rename
    p_ren = sub.add_parser("rename", help="Rename a function or a local variable.")
    p_ren.add_argument("kind", choices=["func", "var"], help="What to rename.")
    p_ren.add_argument("target", help="Function name/address (for `func`) or variable name (for `var`).")
    p_ren.add_argument("new_name", help="New name.")
    p_ren.add_argument("--function", help="When renaming a variable, the containing function.")
    _add_server_filter_args(p_ren)
    _add_output_args(p_ren)
    p_ren.set_defaults(func=cmd_rename)

    # comment
    p_cmt = sub.add_parser(
        "comment",
        help="Get/set/append/delete/list comments (annotations) by address.",
    )
    cmt_sub = p_cmt.add_subparsers(dest="comment_action", required=True)

    def _add_comment_addr_action(name, help_text, with_text=False):
        p = cmt_sub.add_parser(name, help=help_text)
        p.add_argument("addr", help="Address (hex 0x.., decimal, lifted or absolute).")
        if with_text:
            p.add_argument("text", help="Comment text.")
            p.add_argument("--decompiled", action="store_true",
                           help="Attach to the decompiler view (pseudocode) rather than disassembly.")
        _add_server_filter_args(p)
        _add_output_args(p)
        p.set_defaults(func=cmd_comment)
        return p

    _add_comment_addr_action("set", "Set a comment at an address (replaces existing).", with_text=True)
    _add_comment_addr_action("append", "Append text to the comment at an address.", with_text=True)
    _add_comment_addr_action("get", "Print the comment at an address.")
    _add_comment_addr_action("delete", "Delete any comment at an address.")

    p_clist = cmt_sub.add_parser("list", help="List every comment in the binary.")
    p_clist.add_argument("--filter", dest="filter", help="Regex to filter comment text.")
    _add_server_filter_args(p_clist)
    _add_output_args(p_clist)
    p_clist.set_defaults(func=cmd_comment)

    # global
    p_glob = sub.add_parser(
        "global",
        help="List/get/rename/retype global variables.",
    )
    glob_sub = p_glob.add_subparsers(dest="global_action", required=True)

    p_glist = glob_sub.add_parser("list", help="List global variables.")
    p_glist.add_argument("--filter", dest="filter", help="Regex to filter global names.")
    _add_server_filter_args(p_glist)
    _add_output_args(p_glist)
    p_glist.set_defaults(func=cmd_global)

    p_gget = glob_sub.add_parser("get", help="Show a global variable's name/type/size.")
    p_gget.add_argument("addr", help="Address (hex 0x.., decimal, lifted or absolute).")
    _add_server_filter_args(p_gget)
    _add_output_args(p_gget)
    p_gget.set_defaults(func=cmd_global)

    p_gren = glob_sub.add_parser("rename", help="Rename the global variable at an address.")
    p_gren.add_argument("addr", help="Address of the global variable.")
    p_gren.add_argument("new_name", help="New name.")
    _add_server_filter_args(p_gren)
    _add_output_args(p_gren)
    p_gren.set_defaults(func=cmd_global)

    p_gret = glob_sub.add_parser("retype", help="Change the type of the global variable at an address.")
    p_gret.add_argument("addr", help="Address of the global variable.")
    p_gret.add_argument("new_type", help='New C type, e.g. "int", "char[16]", "void *".')
    _add_server_filter_args(p_gret)
    _add_output_args(p_gret)
    p_gret.set_defaults(func=cmd_global)

    # signature
    p_sig = sub.add_parser(
        "signature",
        help="Get or set a function's full signature (return type + argument types/names).",
    )
    sig_sub = p_sig.add_subparsers(dest="signature_action", required=True)

    p_sget = sig_sub.add_parser("get", help="Print a function's C prototype.")
    p_sget.add_argument("function", help="Function name or address.")
    _add_server_filter_args(p_sget)
    _add_output_args(p_sget)
    p_sget.set_defaults(func=cmd_signature)

    p_sset = sig_sub.add_parser("set", help="Set a function's full signature from a C prototype.")
    p_sset.add_argument("function", help="Function name or address.")
    p_sset.add_argument("prototype", help='C prototype, e.g. "int main(int argc, char **argv)".')
    _add_server_filter_args(p_sset)
    _add_output_args(p_sset)
    p_sset.set_defaults(func=cmd_signature)

    # create-type
    p_ct = sub.add_parser(
        "create-type",
        help=(
            "Define a new struct, enum, or typedef from a C definition string "
            "and apply it to the binary's type database."
        ),
    )
    p_ct.add_argument(
        "definition",
        help=(
            'C type definition, e.g. "struct Point { int x; int y; }", '
            '"enum Color { RED, GREEN, BLUE }", or "typedef int my_int_t".'
        ),
    )
    _add_server_filter_args(p_ct)
    _add_output_args(p_ct)
    p_ct.set_defaults(func=cmd_create_type)

    # retype
    p_rt = sub.add_parser(
        "retype",
        help="Change the type of a function's local variable or argument.",
    )
    p_rt.add_argument("function", help="Function name or address (hex/decimal).")
    p_rt.add_argument("variable", help="Variable (stack var or arg) name to retype.")
    p_rt.add_argument("new_type", help='New C type, e.g. "int", "double", "Point *".')
    _add_server_filter_args(p_rt)
    _add_output_args(p_rt)
    p_rt.set_defaults(func=cmd_retype)

    # sync
    p_sync = sub.add_parser(
        "sync",
        help=(
            "Copy work on a function (name, return/arg types, stack vars, and "
            "referenced user types) from one running server into another for "
            "the same binary. Source = --from-id; destination = --id/--binary/--backend."
        ),
    )
    p_sync.add_argument("target", help="Function name or address (hex/decimal) on the source.")
    p_sync.add_argument(
        "--from-id", dest="from_id", required=True,
        help="Source server ID to copy work FROM (see `decompiler list`).",
    )
    _add_server_filter_args(p_sync)
    _add_output_args(p_sync)
    p_sync.set_defaults(func=cmd_sync)

    # list_strings
    p_ls = sub.add_parser(
        "list_strings",
        help=(
            "List strings the decompiler identified in the binary. "
            "Fidelity varies by backend (angr < ghidra < ida) and may be "
            "incomplete — use external tools (strings(1), rabin2 -z, "
            "readelf -p) for an exhaustive scan."
        ),
    )
    p_ls.add_argument("--filter", dest="filter", help="Regex to filter strings.")
    p_ls.add_argument("--min-length", dest="min_length", type=int, default=4,
                      help="Minimum string length to keep (default: 4).")
    _add_server_filter_args(p_ls)
    _add_output_args(p_ls)
    p_ls.set_defaults(func=cmd_list_strings)

    # get_callers
    p_gc = sub.add_parser(
        "get_callers",
        help=(
            "Functions that call a target (call-sites only). "
            "For every reference (code AND data), see `xref_to`."
        ),
    )
    p_gc.add_argument("target", help="Function name or address (hex/decimal).")
    _add_server_filter_args(p_gc)
    _add_output_args(p_gc)
    p_gc.set_defaults(func=cmd_get_callers)

    # read (typed)
    p_read = sub.add_parser(
        "read",
        help="Typed reads: decode memory as an integer, C string, or struct.",
    )
    read_sub = p_read.add_subparsers(dest="read_action", required=True)

    p_rint = read_sub.add_parser("int", help="Read and decode an integer.")
    p_rint.add_argument("addr", help="Address (hex 0x.., decimal, lifted or absolute).")
    p_rint.add_argument("--size", type=lambda x: int(x, 0), default=None,
                        help="Byte width (default: pointer size).")
    p_rint.add_argument("--signed", action="store_true", help="Decode as signed.")
    p_rint.add_argument("--endian", choices=("little", "big"), default="little",
                        help="Byte order (default: little).")
    _add_server_filter_args(p_rint)
    _add_output_args(p_rint)
    p_rint.set_defaults(func=cmd_read)

    p_rstr = read_sub.add_parser("string", help="Read a NUL-terminated C string.")
    p_rstr.add_argument("addr", help="Address of the string.")
    p_rstr.add_argument("--max-len", dest="max_len", type=lambda x: int(x, 0), default=256,
                        help="Maximum bytes to read (default: 256).")
    p_rstr.add_argument("--encoding", default="utf-8", help="Text encoding (default: utf-8).")
    _add_server_filter_args(p_rstr)
    _add_output_args(p_rstr)
    p_rstr.set_defaults(func=cmd_read)

    p_rstruct = read_sub.add_parser("struct", help="Read and decode a defined struct.")
    p_rstruct.add_argument("addr", help="Address of the struct instance.")
    p_rstruct.add_argument("name", help="Name of a defined struct (see `create-type`).")
    p_rstruct.add_argument("--endian", choices=("little", "big"), default="little",
                          help="Byte order for member decoding (default: little).")
    _add_server_filter_args(p_rstruct)
    _add_output_args(p_rstruct)
    p_rstruct.set_defaults(func=cmd_read)

    # read_memory
    p_rm = sub.add_parser(
        "read_memory",
        help=(
            "Read raw bytes from the binary at an address. "
            "Default output is a hexdump; pass --format hex for a single hex "
            "string, --format raw for binary stdout, or --json for a JSON "
            "envelope with base64-encoded bytes."
        ),
    )
    p_rm.add_argument("addr", help="Address to start reading from (hex 0x.. or decimal).")
    p_rm.add_argument("size", type=lambda x: int(x, 0),
                      help="Number of bytes to read (decimal or 0x-prefixed hex).")
    p_rm.add_argument("--format", choices=("hexdump", "hex", "raw"), default="hexdump",
                      help="Text-mode output format. Ignored when --json is set.")
    _add_server_filter_args(p_rm)
    _add_output_args(p_rm)
    p_rm.set_defaults(func=cmd_read_memory)

    # install-skill
    p_sk = sub.add_parser(
        "install-skill",
        help="Install the bundled Agent Skill (SKILL.md) for Claude Code or Codex.",
    )
    p_sk.add_argument("names", nargs="*",
                      help="Specific skill names to install (default: all bundled).")
    p_sk.add_argument(
        "--agent",
        action="append",
        choices=_SKILL_AGENT_CHOICES,
        help=(
            "Agent skill directory to install into. Repeat for multiple agents, "
            "or use 'all'. Default: codex when CODEX_* env vars are present, "
            "otherwise claude."
        ),
    )
    p_sk.add_argument(
        "--dest",
        help="Install destination override. Cannot be combined with --agent.",
    )
    p_sk.add_argument("--force", action="store_true",
                      help="Overwrite an existing skill directory.")
    _add_output_args(p_sk)
    p_sk.set_defaults(func=cmd_install_skill)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(getattr(args, "verbose", False))
    try:
        return args.func(args) or EXIT_OK
    except SystemExit:
        raise
    except NotImplementedError as exc:
        # A backend that doesn't implement the requested capability. Surface a
        # clean, distinct message + exit code so scripts can tell "unsupported
        # on this backend" apart from a genuine failure.
        msg = str(exc) or "not implemented for this backend"
        print(f"not implemented: {msg}", file=sys.stderr)
        return EXIT_UNSUPPORTED
    except Exception as exc:  # noqa: BLE001
        _l.exception("Unhandled error: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
