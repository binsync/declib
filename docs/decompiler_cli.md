# `decompiler` CLI

The `decompiler` command is a thin, LLM-friendly client over DecLib. You load a
binary once (which spawns a headless decompiler server in the background) and
then run quick inspection or mutation commands against it. Multiple binaries
and backends can be loaded at the same time; each server is identified by a
short ID.

<img width="856" height="607" alt="image" src="https://github.com/user-attachments/assets/7da48494-5f56-4f6d-bad6-97a75d8038c5" />

This document is for humans; the short reference version used by LLM agents
lives at [`declib/skills/decompiler/SKILL.md`](../declib/skills/decompiler/SKILL.md)
and can be installed with `decompiler install-skill`.

---

## Table of contents

- [Install & setup](#install--setup)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Subcommand reference](#subcommand-reference)
  - [`load`](#load)
  - [`list`](#list)
  - [`stop`](#stop)
  - [`list_functions`](#list_functions)
  - [`decompile`](#decompile)
  - [`disassemble`](#disassemble)
  - [`xref_to`](#xref_to)
  - [`xref_from`](#xref_from)
  - [`rename`](#rename)
  - [`list_strings`](#list_strings)
  - [`get_callers`](#get_callers)
  - [`install-skill`](#install-skill)
- [Server selection (`--id`, `--binary`, `--backend`)](#server-selection)
- [JSON output (`--json`, `--raw`)](#json-output)
- [Exit codes](#exit-codes)
- [Running multiple binaries at once](#running-multiple-binaries-at-once)
- [Address formats](#address-formats)
- [Library-level API](#library-level-api)
- [Troubleshooting](#troubleshooting)

---

## Install & setup

```bash
pip install declib
# Register DecLib plugins into every detected decompiler.
declib --install
# Or point the installer at one specific decompiler:
declib --single-decompiler-install binja "/Applications/Binary Ninja.app"
```

After `pip install declib`, two entry points are available:

- `declib` — the existing management CLI (install plugins, run the server,
  etc.)
- `decompiler` — the new LLM-facing CLI documented here.

Pick a backend you have available:

- **angr** — pure Python, always available. Good for end-to-end testing and
  small/medium binaries.
- **ghidra** — requires `GHIDRA_INSTALL_DIR` and uses PyGhidra.
- **binja** — requires a Binary Ninja license.
- **ida** — requires IDA Pro.

---

## Quick start

```bash
# 1. Load a binary. The first call spawns a detached headless server.
decompiler load ./fauxware --backend angr
# id: 3308b81cf8 …

# 2. Poke around.
decompiler list_functions                    # enumerate every function first
decompiler decompile main                    # by name
decompiler disassemble 0x40071d              # by absolute address
decompiler xref_to authenticate              # every code+data reference
decompiler get_callers authenticate          # call-sites only (subset of xref_to)
decompiler xref_from main                    # what main calls
decompiler list_strings --filter 'pass|key'  # regex-filtered strings

# 3. Mutate the database.
decompiler rename func sub_400662 trampoline
decompiler rename var v2 auth_result --function main

# 4. Tear it down when you're done.
decompiler stop --all
```

---

## How it works

```
┌─────────────┐      spawns       ┌─────────────────────────┐
│  decompiler │ ────────────────▶ │ declib --server (headless│
│     CLI     │   (first load)    │ decompiler + AF_UNIX    │
│             │                   │ socket)                 │
│             │ ◀─────────────────│                         │
└─────────────┘   every command   └─────────────────────────┘
        │
        ▼
~/.local/state/declib/servers/<id>.json  ← the shared registry
```

Each running server writes a small JSON descriptor (`id`, `socket_path`,
`binary_path`, `binary_hash`, `backend`, `pid`, `started_at`) into a shared
registry directory. The CLI reads the registry to figure out which server to
talk to. Stale records (server exited, socket missing) are pruned on read.
Run `decompiler list --show-registry` to print just the path.

Every subcommand except `load`, `list`, and `install-skill` accepts
`--id`, `--binary`, and `--backend` to pick which server to target when you
have more than one running.

---

## Subcommand reference

### `load`

Load a binary, starting a headless server if one isn't already running for
it.

```bash
decompiler load <binary> [--backend {angr,ghidra,binja,ida}]
                         [--id SERVER_ID]
                         [--force | --replace]
                         [--project-dir PATH]
                         [--json]
```

- **`--backend`** (default: `angr`) — which decompiler to use.
- **`--id`** — explicit server ID; otherwise one is auto-generated.
- **`--force`** — start an additional server even if one already matches
  this `(binary, backend)`. Keeps the old server alive.
- **`--replace`** — stop any existing server for this `(binary, backend)`
  first, then start a fresh one. Use this when you want to re-analyze from
  scratch.
- **`--project-dir PATH`** — where to keep the backend's
  project/database files (Ghidra project, IDA `.id*`/`.til`, etc.).
  Default: a per-binary directory under the user cache
  (`<platformdirs cache>/declib/projects/<binary>-<hash>/`), so analysis
  artifacts don't pollute the binary's directory. Pass `--project-dir ""`
  to disable the cache dir and let the backend drop files alongside the
  binary (legacy behavior).

Outputs `id`, `socket_path`, `binary_path`, `backend`, `project_dir`, and
`status` (either `started` or `already_loaded`).

### `list`

Show all running decompiler servers.

```bash
decompiler list [--show-registry] [--json]
```

Text output:

```
ID           BACKEND  PID      BINARY
3308b81cf8   angr     57613    /…/fauxware
9d77ab8fd4   angr     57786    /…/posix_syscall

(registry: /Users/me/Library/Application Support/declib/servers)
```

- **`--show-registry`** — print the registry directory and exit (useful for
  scripting manual cleanup).
- **`--json`** emits `{"registry_dir": "...", "servers": [...]}`.

### `stop`

Stop one or all servers.

```bash
decompiler stop [--id SERVER_ID] [--binary PATH] [--all] [--save | --discard] [--json]
```

You must pass one of `--id`, `--binary`, or `--all`. By default the backend's
native teardown applies (IDA discards, Ghidra persists). Pass `--save` to flush
analysis to disk first (durable across a reload), or `--discard` to explicitly
drop unsaved edits. `--save` and `--discard` are mutually exclusive.

### `save`

Persist the backend's analysis to disk so renames, retypes, and comments
survive a `stop` + reload of the same `--project-dir`.

```bash
decompiler save [--path PATH] [--id ID] [--binary PATH] [--backend BACKEND] [--json]
```

Each backend writes its native artifact: IDA a `.i64`/`.idb`, Ghidra its
project, Binary Ninja a `.bndb`. `angr` is purely in-memory and has nothing to
persist — `save` exits `2` (`not implemented`) there. On reload, DecLib reopens
the saved database (IDA does so without re-analysis), so prior work is intact.

```bash
decompiler load ./fauxware --backend ida --project-dir ./proj
decompiler rename func authenticate auth_check
decompiler save                       # {"saved": true, "path": null}
decompiler stop --id <id>
decompiler load ./fauxware --backend ida --project-dir ./proj  # reopens saved .i64
decompiler list_functions --filter auth_check   # rename survived
```

### `list_functions`

Enumerate every function in the loaded binary. This is usually the first
thing you want on a new (possibly stripped) binary.

```bash
decompiler list_functions [--filter REGEX] [--id ID] [--binary PATH] [--backend BACKEND] [--json]
```

Text output:

```
ADDR         SIZE     NAME
0x540        6        __libc_start_main
0x71d        184      main
0x664        184      authenticate
...
```

JSON output is a list of `{"addr": int, "size": int, "name": str, "addr_hex": str}`.

### `decompile`

Decompile a function to pseudocode.

```bash
decompiler decompile <target> [--raw] [--id ID] [--binary PATH] [--backend BACKEND] [--json]
```

`<target>` is a function name or address (hex/decimal, lifted or absolute —
see [Address formats](#address-formats)).

- **`--raw`** — print the decompilation text directly, skipping all
  wrapping. Useful at a terminal when `--json`'s escaped `\n`s are
  unreadable.

Default text output is the decompilation. JSON output includes `addr`,
`addr_hex`, `decompiler`, and `text`.

Error messages distinguish three failure modes:

- **target not found** — function name/address doesn't resolve.
- **not a function start** — address resolves, but isn't a function
  boundary. Exit 1.
- **decompiler engine failed** — address is a known function start, but
  the backend gave up. Exit 1.

### `disassemble`

Disassemble a function to text assembly.

```bash
decompiler disassemble <target> [--raw] [--id ID] [--binary PATH] [--backend BACKEND] [--json]
```

Same error semantics and `--raw` flag as `decompile`.

### `xref_to`

**Every reference** to `target` — code AND data.

```bash
decompiler xref_to <target> [--decompile] [--id ID] [--binary PATH] [--backend BACKEND] [--json]
```

`<target>` can be:

- a **function name or address** — resolves to function xrefs (who calls
  this function),
- a **raw address** that isn't a function start — resolves via the
  backend's address-level reference table (useful for globals, jump
  table entries, etc.),
- a **string literal** — looked up via `list_strings` first, then queried
  as a raw-address xref. Great for "who reads this constant?".

Each row has a `kind` field (`Function`, `GlobalVariable`, …) so you can
tell code refs from data refs. The JSON payload also carries
`target_kind` (`function`, `address`, or `string`) so callers can tell
which resolution path fired.

- **`--decompile`** — ask the backend to decompile first. On Ghidra this
  surfaces additional references (e.g. globals pulled in through the
  HighFunction's global symbol map).

When you want only call-sites, reach for `get_callers` instead.

### `xref_from`

Functions that `target` calls (its callees).

```bash
decompiler xref_from <target> [--id ID] [--binary PATH] [--backend BACKEND] [--json]
```

Implementation note: this prefers the backend's call-graph. If the
call-graph is unavailable it falls back to scanning the function's
disassembly for `call 0x…` instructions.

### `rename`

Rename a function or a local variable.

```bash
# Rename a function.
decompiler rename func <old_name_or_addr> <new_name> [--id ID] [--json]

# Rename a local variable inside a function.
decompiler rename var <old_var_name> <new_var_name> --function <func_name_or_addr> [--id ID] [--json]
```

The CLI exits `1` if the rename didn't actually change anything (the
response's `success` field is authoritative).

### `comment`

Get, set, append, delete, or list comments (annotations), keyed by address.

```bash
decompiler comment set <addr> <text> [--decompiled] [--id ID] [--json]
decompiler comment append <addr> <text> [--decompiled] [--id ID] [--json]
decompiler comment get <addr> [--id ID] [--json]
decompiler comment delete <addr> [--id ID] [--json]
decompiler comment list [--filter REGEX] [--id ID] [--json]
```

`--decompiled` attaches the comment to the decompiler/pseudocode view instead
of the disassembly. `set` replaces any existing comment; `append` concatenates.
`get` exits `1` when there is no comment at the address.

```bash
decompiler comment set 0x71d "parses argv, calls authenticate"
decompiler comment append 0x71d "SOSNEAKY is the backdoor password"
decompiler comment get 0x71d
# {"addr": 1821, "decompiled": false, "comment": "parses argv, calls authenticate\nSOSNEAKY is the backdoor password", "addr_hex": "0x71d"}
decompiler comment list --filter backdoor --json
```

Backend notes: IDA accepts comments only at addresses **inside a function**;
Ghidra and Binary Ninja are more permissive. `angr` implements comment writes
but not reads/enumeration, so `get`/`list` return nothing there. Use `save`
(or `stop --save`) to persist comments across a reload.

### `global`

List, read, rename, or retype global variables.

```bash
decompiler global list [--filter REGEX] [--id ID] [--json]
decompiler global get <addr> [--id ID] [--json]
decompiler global rename <addr> <new_name> [--id ID] [--json]
decompiler global retype <addr> <new_type> [--id ID] [--json]
```

```bash
decompiler global list --filter 'key|flag'
# ADDR         SIZE   TYPE                 NAME
# 0x4040       8      char *               g_key
decompiler global rename 0x4040 g_secret_key
decompiler global retype 0x4040 "char[32]"
```

`rename` works everywhere globals are enumerated; `retype` is fully supported
on IDA and Binary Ninja, best-effort on Ghidra. `angr` has no global-variable
store, so its `global` commands return nothing.

### `signature`

Get or set a function's full signature (return type + argument types/names).

```bash
decompiler signature get <func> [--id ID] [--json]
decompiler signature set <func> "<C prototype>" [--id ID] [--json]
```

```bash
decompiler signature get main
# int main(int argc, char **argv)
decompiler signature set main "int main(int argc, char **argv, char **envp)"
```

IDA applies the whole prototype atomically via `SetType` (it can also change the
parameter count). Ghidra and Binary Ninja retype/rename the parameters they
already recognize. `angr` sets argument names but not types.

### `list_strings`

List strings the decompiler's own string detector has identified in the
binary.

```bash
decompiler list_strings [--filter REGEX]
                        [--min-length N]
                        [--id ID] [--binary PATH] [--backend BACKEND] [--json]
```

- **`--filter REGEX`** — only return strings matching the regex.
- **`--min-length N`** — drop strings shorter than N characters (default 4).

Text output is `0x<addr>\t<string>` per line. JSON output is a list of
`{"addr", "addr_hex", "string"}` entries.

**Fidelity caveat.** This command only returns what the decompiler
itself surfaced — it does not second-guess the backend or supplement with
a file-level scan. Backend string detection quality varies
(`angr < ghidra < ida`); angr in particular misses most of `.rodata`.
If the output looks thin, cross-check with an external tool before
concluding a string isn't in the binary:

```bash
strings -a -n 4 ./target       # classic strings(1)
rabin2 -z ./target             # radare2, structured output
readelf -p .rodata ./target    # ELF-specific, per section
```

Once you've located a string that way you can feed its address back into
the CLI via `decompiler xref_to 0x...` or `decompiler decompile 0x...`.

### `get_callers`

Functions that contain a call to `target` — a strict subset of `xref_to`.

```bash
decompiler get_callers <target> [--id ID] [--binary PATH] [--backend BACKEND] [--json]
```

Unlike `xref_to`, this never returns globals or other data refs. Rows are
always of kind `Function`.

### `install-skill`

Copy the bundled Agent Skill into a supported agent skill directory so Claude
Code or Codex learns how to drive the CLI.

```bash
decompiler install-skill [names ...] [--agent claude|codex|all] [--dest DIR] [--force] [--json]
```

With no `names`, every bundled skill is installed. By default the installer
uses Codex when `CODEX_*` environment variables are present, otherwise Claude.
Use `--agent codex`, `--agent claude`, repeated `--agent` flags, or
`--agent all` to choose explicitly. Claude installs under `~/.claude/skills`;
Codex installs under `$CODEX_HOME/skills` when `CODEX_HOME` is set, otherwise
`~/.codex/skills`.

Use `--dest` to copy the skill somewhere else, and `--force` to overwrite an
existing directory. `--json` emits a well-formed JSON payload suitable for
piping through `jq`.

---

## Server selection

When more than one server is running, the inspection/mutation commands need
to know which one to talk to. Narrow with any combination of:

- **`--id <SERVER_ID>`** — exact match.
- **`--binary <PATH>`** — match by binary path (resolved to an absolute
  path).
- **`--backend <angr|ghidra|binja|ida>`** — match by backend.

If zero servers match, the CLI errors out and tells you to run
`decompiler load`. If multiple match, it prints a disambiguation list:

```
Multiple servers match. Specify --id to disambiguate:
  3308b81cf8  backend=angr  binary=/…/fauxware
  9d77ab8fd4  backend=angr  binary=/…/posix_syscall
```

---

## JSON output

Pass `--json` on any subcommand to get a structured payload suitable for
downstream parsing. This is the recommended mode for scripts and LLM
callers. Every JSON payload that mentions an address provides both
`addr` (integer, lifted) and `addr_hex` (hex string, also lifted), so you
can copy either form without re-formatting:

```bash
decompiler list_functions --filter '^main$' --json
# [{"addr": 1821, "size": 184, "name": "main", "addr_hex": "0x71d"}]

decompiler xref_to authenticate --json
# {"addr": 1636, "direction": "to",
#  "xrefs": [{"kind": "Function", "addr": 1821, "name": "main", "addr_hex": "0x71d"}, ...],
#  "addr_hex": "0x664"}
```

For decompile/disassemble output, JSON wraps the text in a `text` field
with escaped newlines. At a terminal this is awkward; pass `--raw`
instead:

```bash
decompiler decompile main --raw         # prints the pseudocode directly
decompiler disassemble 0x71d --raw      # prints assembly directly
```

---

## Exit codes

Every CLI command uses these exit codes:

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | User-visible error — target not found, rename didn't apply, decompile failed, etc. Most failure modes unify to `1` so that shell `&&` chaining works cleanly. |
| `2` | The requested capability is **not implemented for the selected backend** (e.g. `save` on angr). Distinct from `1` so scripts can branch on "unsupported" vs "failed". |

Argparse-level errors (unknown subcommand, missing required argument) also exit
with Python's standard argparse code `2`.

---

## Running multiple binaries at once

```bash
decompiler load ./my-binary                # id=abc1234
decompiler load ./my-binary-2              # id=def5678

decompiler list
# ID           BACKEND  PID      BINARY
# abc1234...   angr     4213     .../my-binary
# def5678...   angr     4217     .../my-binary-2
#
# (registry: /…/declib/servers)

# Target by ID …
decompiler decompile main --id abc1234

# … or by binary path.
decompiler decompile main --binary ./my-binary-2

# Restart a server cleanly (stop existing, spawn fresh):
decompiler load ./my-binary --replace

# Run an additional server alongside the existing one:
decompiler load ./my-binary --force

# Tear them all down.
decompiler stop --all
```

You can even mix backends on the same binary — add `--force` to `load` to
launch a second server for the same file:

```bash
decompiler load ./bin --backend ghidra
decompiler load ./bin --backend angr --force
decompiler decompile main --binary ./bin --backend ghidra
decompiler decompile main --binary ./bin --backend angr
```

---

## Address formats

DecLib normalizes addresses to a **lifted** form (relative to the binary's
base address), so artifacts stay stable across decompilers. The CLI, though,
accepts whatever is natural for the user:

- `0x71d`, `1821` — lifted
- `0x40071d` — absolute (base + lifted)
- `main` — symbol name

The CLI converts on the fly. The returned `addr` fields in JSON output are
**always lifted**, which matches what the server's artifact dictionaries
use. `addr_hex` is the same value as a hex string for convenience.

---

## Library-level API

Everything the CLI does is also available as a library — useful when you
want to chain operations or integrate DecLib into a larger tool:

```python
from declib.api.decompiler_client import DecompilerClient

# Pick a running server out of the shared registry.
client = DecompilerClient.discover_from_registry(binary_path="./fauxware")

for addr, func in client.functions.items():
    if func.name == "main":
        print(client.decompile(addr).text)
        print(client.disassemble(addr))
        for caller in client.get_callers(addr):
            print(caller.addr, caller.name)
```

The three APIs added to power the CLI are also usable directly through
`DecompilerInterface` (headless/embedded) and `DecompilerClient` (remote):

- `list_strings(filter: str | None = None) -> list[tuple[int, str]]`
- `get_callers(target: Function | int | str) -> list[Function]`
- `disassemble(addr: int) -> str | None`

Backends currently implementing them: angr and Ghidra. IDA and Binary Ninja
fall back to the default implementations.

---

## Troubleshooting

**`No running decompiler server matches …`**
You haven't loaded the binary yet. Run
`decompiler load <binary> --backend <backend>` first, or use
`decompiler list` to see what's already running.

**`Multiple servers match. Specify --id to disambiguate`**
Two servers match your filters. Either pass `--id` with one of the printed
IDs, or narrow with `--binary`/`--backend`.

**`Timed out waiting … for server … to start.`**
The detached server process didn't come up in time (default 5 minutes).
Check backend prerequisites:
- Ghidra: `GHIDRA_INSTALL_DIR` must be set.
- IDA/Binary Ninja: their Python bindings must be importable.
- angr: should just work.

**`No function starts at 0x…`**
The address is valid in the binary but doesn't correspond to the first
byte of any known function. Use `decompiler list_functions` to find a
valid start. (Prior to v2 this was reported with the same error as
"decompiler engine failed"; they're now distinct.)

**Rename reports `success: False` (exit 1)**
The old name was not found in the function (e.g. it was already renamed,
or you targeted the wrong function).

**`list_strings` looks thin**
This is expected on angr (and can happen on Ghidra for stripped binaries) —
`list_strings` returns only what the decompiler itself identified. Use an
external scanner to see every ASCII constant in the file, then feed the
address back into `xref_to` / `decompile`:

```bash
strings -a -n 4 ./target
rabin2 -z ./target
readelf -p .rodata ./target
```

**Server-side logs**
Spawned servers have their stdout/stderr sent to `/dev/null`. If you're
debugging server startup, start one by hand in a foreground terminal:

```bash
declib --server --headless --decompiler angr --binary-path ./bin --server-id my-srv
```

That will print log output to the terminal, and the CLI in another terminal
can still drive it via `decompiler decompile main --id my-srv`.
