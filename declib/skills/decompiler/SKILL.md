---
name: decompiler
description: Reverse-engineer and modify binaries with a single `decompiler` CLI that drives IDA Pro, Ghidra, Binary Ninja, or angr via DecLib. Use whenever the user asks to decompile, disassemble, look up cross references, rename functions or variables, define or change types, sync work between decompilers, search strings or functions, or otherwise inspect a binary file. Also use for multi-binary workflows (load several binaries at once and switch between them with --id).
---

# `decompiler` — DecLib CLI for LLMs

The `decompiler` command is a thin client that talks to a long-running
`DecompilerServer` (IDA / Ghidra / Binary Ninja / angr). The first `load` of a
binary spawns a server in the background; every subsequent call reuses that
server, so repeated `decompile`/`disassemble`/`xref_*` calls are fast.

## Setup (once per environment)

```bash
pip install declib          # installs the `decompiler` and `declib` entry points
```

That's it — the `decompiler` CLI drives every backend headlessly via DecLib
and does **not** need any plugins installed inside IDA/Ghidra/Binary Ninja
to run. `angr` needs no host tool at all (it's a pure Python dependency)
and is the fastest way to verify the pipeline end-to-end.

## Mental model

| Concept | Description |
|---|---|
| **Server** | A headless `declib --server` process holding a single binary open. Identified by a short ID. |
| **Client** | Every `decompiler <subcommand>` call is a short-lived client that picks a server, does one thing, and exits. |
| **Registry** | `decompiler list` / the shared registry under the declib state dir. Each record has `id`, `backend`, `binary_path`, `socket_path`, `pid`. Use `decompiler list --show-registry` to print just the path. |
| **Address form** | Servers expose **lifted** addresses (relative to the binary base). The CLI accepts either lifted (`0x71d`) or absolute (`0x40071d`) and does the conversion. JSON output always includes both `addr` (int) and `addr_hex` (hex string). |

## First moves on a new binary

**Always prefer IDA Pro when it's available** (`--backend ida`) — it
generally produces the cleanest decompilation and the most accurate type
recovery. If IDA fails to load the binary (missing license, unsupported
file type, decompiler error), fall back to `--backend ghidra`, then
`--backend angr` as a last resort.

**Always start with `list_functions` and `list_strings`** — the same binary
can have the entry named `main` (angr), `FUN_00101c5c` (Ghidra), or
`sub_101c5c` (IDA). Don't assume `main` exists.

```bash
decompiler load ./target --backend ida         # prefer IDA; fall back to ghidra if it fails
decompiler list_functions                      # enumerate every function — pick a real entry
decompiler list_functions --filter 'main|auth' # or narrow by regex
decompiler list_strings --filter 'flag|pass'   # find interesting string constants
```

Typical first-hour workflow on a stripped binary:

1. `decompiler load ./bin --backend ida` (fall back to `--backend ghidra`,
   then `--backend angr`, if IDA can't open the binary)
2. `decompiler list_functions` → note non-stub function names + sizes
3. `decompiler list_strings` → look for error messages, user prompts,
   format strings — they often point at the interesting code
4. `decompiler xref_to "Welcome"` → jump from a string to its users
5. `decompiler decompile <addr>` on whichever function came out of steps 3–4

## Core workflow

```bash
decompiler load ./fauxware --backend ida      # start a server (prefer IDA)
decompiler list_functions                     # enumerate functions (do this first)
decompiler list_strings --filter 'pass|key'   # strings the decompiler identified
decompiler xref_to SOSNEAKY                   # who references this string?
decompiler decompile authenticate             # by name (from list_functions)
decompiler disassemble 0x40071d               # by absolute address
decompiler xref_to authenticate               # every code+data reference
decompiler get_callers authenticate           # call-sites only (subset of xref_to)
decompiler xref_from main                     # what does main call?
decompiler rename func sub_400662 trampoline  # rename a function
decompiler rename var v2 auth_result --function main  # rename a local
decompiler create-type "struct Point { int x; int y; }"   # define a new type
decompiler retype main buf "Point *"          # set a variable's type
decompiler stop --all
```

## Running multiple binaries concurrently

Each binary gets its own server ID:

```bash
decompiler load ./my-binary            # id=abc1234
decompiler load ./my-binary-2          # id=def5678
decompiler list
# ID           BACKEND  PID      BINARY
# abc1234...   angr     4213     .../my-binary
# def5678...   angr     4217     .../my-binary-2
decompiler decompile main --id abc1234
decompiler decompile main --binary ./my-binary-2   # or target by path
```

When more than one server matches, the CLI refuses and prints a
disambiguation list. Narrow with `--id`, `--binary`, or `--backend`. If you
want to restart the server for a binary cleanly, use `load ... --replace`
which stops the old server and starts a new one (vs `--force` which adds a
second server alongside the existing one).

## Choosing a backend

**Default: IDA Pro.** Use `--backend ida` whenever IDA is installed and
licensed — its decompilation is the most reliable across architectures.
Only switch backends if IDA fails to load the binary (the `load` call
errors, or analysis stalls); fall through in this order: `ida → ghidra
→ angr`. Use `binja` only when explicitly requested.

```bash
decompiler load ./my-binary --backend ida      # PREFERRED: IDA Pro (needs install + license)
decompiler load ./my-binary --backend ghidra   # FALLBACK: needs GHIDRA_INSTALL_DIR
decompiler load ./my-binary --backend angr     # LAST RESORT: pure-Python, always available
decompiler load ./my-binary --backend binja    # Binary Ninja, needs license
```

If the IDA `load` fails (e.g. unsupported file format, decompiler error),
re-issue `load` with `--backend ghidra` — `load` is idempotent per
backend, so this leaves any other server alone and just brings up a
Ghidra one alongside.

`--backend` is also accepted on the inspection/mutation subcommands to
narrow which server to target when multiple backends are loaded for the
same binary.

## Full subcommand reference

| Subcommand | Purpose | Key flags |
|---|---|---|
| `load <bin>` | Start a server on the binary. Idempotent: returns existing unless `--force`/`--replace`. | `--backend`, `--id`, `--force`, `--replace`, `--project-dir`, `--json` |
| `list` | Show all running servers and the registry path. | `--show-registry`, `--json` |
| `stop` | Shut down one or all servers. `--save` flushes analysis to disk first; `--discard` drops unsaved edits. | `--id`, `--binary`, `--all`, `--save`, `--discard`, `--json` |
| `save` | Persist backend analysis to disk so renames/types/comments survive a reload. | `--path`, `--id`, `--binary`, `--backend`, `--json` |
| `list_functions` | Enumerate every function (ADDR, SIZE, NAME). | `--filter REGEX`, `--json` |
| `decompile <target>` | Pseudocode for a function (name or address). | `--raw`, `--id`, `--binary`, `--backend`, `--json` |
| `disassemble <target>` | Assembly for a function. | `--raw`, same |
| `xref_to <target>` | Every reference (code + data) to the target. | `--decompile`, same |
| `xref_from <target>` | Functions that `target` calls. | same |
| `comment set/append <addr> <text>` | Set (replace) or append a comment at an address. `--decompiled` attaches it to the pseudocode view. | `--decompiled`, same + `--json` |
| `comment get/delete <addr>` | Read or remove the comment at an address. | same |
| `comment list` | List every comment in the binary. | `--filter REGEX`, same |
| `rename func <target> <new>` | Rename a function. | same + `--json` |
| `rename var <old> <new> --function <f>` | Rename a local variable inside a function. | same |
| `global list` | List global variables (ADDR, SIZE, TYPE, NAME). | `--filter REGEX`, same |
| `global get/rename/retype <addr> [...]` | Read, rename, or retype the global at an address. | same |
| `signature get <func>` | Print a function's full C prototype. | same |
| `signature set <func> "<C prototype>"` | Set return type + argument types/names from a prototype. | same |
| `create-type "<C definition>"` | Define a new `struct`/`enum`/`typedef` from a C string and add it to the type database. | same + `--json` |
| `retype <func> <var> <type>` | Set the type of a function's local variable or argument. | same |
| `sync <func> --from-id <src>` | Copy a function's work (names, return/arg types, stack-var names+types, referenced user types) from one running server into another for the same binary. | dest: `--id`/`--binary`/`--backend`; `--json` |
| `list_strings` | Strings the decompiler found (may be incomplete — see below). | `--filter`, `--min-length N`, same |
| `get_callers <target>` | Call-sites only — subset of `xref_to`. | same |
| `read_memory <addr> <size>` | Read raw bytes from the binary at `<addr>`. Default output is a hexdump. | `--format {hexdump,hex,raw}`, same + `--json` (base64-encoded bytes) |
| `install-skill` | Install this file for Claude Code or Codex. | `--agent`, `--dest`, `--force`, `--json` |

### `xref_to` vs `get_callers`

- `xref_to` asks the backend for **every reference** — code *and* data. On
  Ghidra with `--decompile` this includes global variables and string
  references. Rows include a `kind` field (`Function`, `GlobalVariable`,
  ...). `xref_to` also accepts **strings and raw addresses**: if the
  target isn't a function, it's looked up in `list_strings` first, then
  queried as a raw-address xref — so you can go straight from
  `list_strings --filter "admin"` to `xref_to admin` to find who reads
  that constant.
- `get_callers` is the narrower call-sites-only view: only functions that
  contain a `call` to the target. When you want "who calls this?" reach
  for `get_callers`; when you want "who touches this in any way?" reach
  for `xref_to`.

### `comment` — annotate addresses

Comments are the primary way to leave durable notes for later (or for another
agent). They are keyed by address and come in two flavors: disassembly comments
(default) and decompiler/pseudocode comments (`--decompiled`).

```bash
decompiler comment set 0x71d "entry point; parses argv"     # replace
decompiler comment append 0x71d "calls authenticate()"       # add a line
decompiler comment set 0x664 "SOSNEAKY backdoor" --decompiled
decompiler comment get 0x71d                                 # print it (exit 1 if none)
decompiler comment list --filter backdoor                    # find comments by text
decompiler comment delete 0x71d
```

Addresses accept the usual lifted/absolute/decimal forms. `comment set` writes
through the backend, so on IDA the address must be **inside a function**
(disassembly comments elsewhere aren't supported by IDA's API). `angr`
implements comment writes but not reads/enumeration yet — `comment get`/`list`
return nothing there. Pair with `save` to make comments durable across reloads.

### `global` and `signature` — globals and full prototypes

```bash
decompiler global list --filter 'key|flag'      # ADDR SIZE TYPE NAME
decompiler global get 0x4008 --json
decompiler global rename 0x4008 g_secret_key
decompiler global retype 0x4008 "char[32]"

decompiler signature get main                   # int main(int argc, char **argv)
decompiler signature set main "int main(int argc, char **argv)"
```

`signature set` takes a full C prototype and applies the return type plus each
argument's type and name. IDA applies the whole prototype atomically (it can
also change the parameter count); Ghidra/Binary Ninja retype and rename the
parameters they already recognize. `angr` sets argument *names* but not types.
`global retype` is fully supported on IDA/Binary Ninja and best-effort on
Ghidra; `angr` has no global-variable store (its `global` commands return
nothing).

### Persistence — durable artifacts (`save`, `stop --save`)

By default a server holds the binary open in memory; IDA discards edits on
stop, while Ghidra persists on close. To make renames/types/comments **durable**
regardless of backend, `save` explicitly, or stop with `--save`:

```bash
decompiler load ./fauxware --backend ida --project-dir ./proj
decompiler rename func authenticate auth_check
decompiler save                       # writes ./proj/ida/fauxware.i64
decompiler stop --id <id>
decompiler load ./fauxware --backend ida --project-dir ./proj  # reopens saved DB
decompiler list_functions --filter auth_check   # the rename is still there
# {"saved": true, "path": null}

decompiler stop --all --save          # flush every server before shutting down
decompiler stop --id <id> --discard   # drop unsaved edits (revert to analyzed state)
```

Reuse the **same `--project-dir`** across load/reload so the backend finds its
saved database (IDA `.i64`, Ghidra project, Binary Ninja `.bndb`). `angr` is
purely in-memory: `save` exits `2` (`not implemented`) and there is nothing to
reload. IDA reopens the saved `.i64` directly (no re-analysis), so a reload after
`save` is fast and lossless.

### `read_memory` — raw bytes at an address

`read_memory <addr> <size>` reads `<size>` bytes from the loaded binary's
mapped memory starting at `<addr>`. It goes through the backend's own
memory accessor, so it returns whatever the decompiler currently has
loaded for that address (post-relocation, post-mapping) — not the raw
bytes from the on-disk ELF/PE/Mach-O. Use it when you need to:

- Inspect a constant table, jump table, or vtable that the decompiler
  rendered as `dword_<addr>` / `unk_<addr>`.
- Read a string the backend's string detector missed (cross-check
  against `list_strings` first; if absent, dump bytes manually).
- Verify the actual bytes behind a global the decompiler shows as an
  opaque symbol.
- Pull a magic header / signature out of `.rodata` to confirm a file
  format or library version.

```bash
decompiler read_memory 0x4008e0 64                       # default: hexdump
decompiler read_memory 0x4008e0 64 --format hex          # one-line hex blob
decompiler read_memory 0x4008e0 64 --format raw > bytes  # raw bytes to a file
decompiler read_memory 0x4008e0 64 --json                # base64-encoded payload
```

JSON output includes both `size` (actual bytes returned) and
`requested_size` — backends may produce **short reads** when the request
straddles the end of a mapped segment. In text mode the CLI prints a
`# short read: ...` notice on stderr in that case. If the address is
unmapped or uninitialized, the CLI exits non-zero with a message saying
the backend couldn't satisfy the read; try a smaller `size` or confirm
the address with `list_functions` / `xref_to`.

Address formats follow the same rules as everywhere else: hex (`0x4008e0`),
decimal (`4197088`), or lifted (`0x8e0`) all work.

### Editing types and syncing across decompilers

`create-type` parses a C type *definition* and adds it to the binary's type
database. `retype` then points a variable at it (or at any built-in type).
Both work on every backend; refer to the struct by name, with `*`/`[]` for
pointers and arrays:

```bash
decompiler create-type "struct Point { int x; int y; }"
decompiler create-type "enum Color { RED, GREEN=5, BLUE }"
decompiler retype main buf "Point *"          # stack var or argument, by name
```

`sync` copies one function's work from a **source** server into a
**destination** server for the *same* binary — handy when you reverse a
function in one tool and want it mirrored in another. It transfers the
function name, return/argument types, stack-variable names and types, and
any user-defined types those reference. The source is chosen with
`--from-id`; the destination with the usual `--id`/`--binary`/`--backend`:

```bash
decompiler load ./fauxware --backend ida      # id=ida123  (do your work here)
decompiler load ./fauxware --backend ghidra   # id=ghi456
decompiler rename func 0x71d auth_check --id ida123
decompiler retype 0x71d buf "Point *" --id ida123
decompiler sync 0x71d --from-id ida123 --id ghi456   # push it into Ghidra
```

Addresses and stack-variable offsets are normalized, so the function and
its variables re-key correctly even when the two backends name them
differently. Pass a function **address** (most robust) or a name.

### `list_strings` may be incomplete

`list_strings` returns exactly what the backend's own string detector
surfaced — the CLI does not second-guess the decompiler. Fidelity varies
(`angr < ghidra < ida`); angr in particular misses most of `.rodata`. If
the output looks thin, check the binary file directly with an external
scanner:

```bash
strings -a -n 4 ./target          # classic strings(1)
rabin2 -z ./target                # radare2: ASCII data-section scan
readelf -p .rodata ./target       # ELF-specific, per section
```

Use those to confirm a specific constant exists, then come back and
`decompile` / `xref_to` its address inside the CLI. `--min-length`
defaults to 4.

## Machine-readable output

Pass `--json` on any subcommand to get a structured payload suitable for
downstream parsing — ideal when an LLM wants to chain commands. Every
JSON payload that mentions an address provides both `addr` (int, lifted)
and `addr_hex` (hex string, also lifted):

```bash
decompiler list_functions --filter '^main$' --json
# [{"addr": 1821, "size": 184, "name": "main", "addr_hex": "0x71d"}]

decompiler list_strings --filter 'flag' --json
# [{"addr": 4197168, "string": "flag{...}", "addr_hex": "0x4008e0"}]

decompiler decompile main --json
# {"addr": 1821, "decompiler": "angr", "text": "void main(...){...}", "addr_hex": "0x71d"}

# Terminal-friendly form of decompile: skip JSON wrapping entirely.
decompiler decompile main --raw
```

## Gotchas and tips

- **First `load` is slow** (backend analysis pass). Subsequent calls on the
  same server are fast.
- **Exit codes**: every CLI command exits `0` on success and `1`
  on failure (including "rename didn't find the old name"). Exit `2` means
  the feature is **not implemented for the selected backend** (e.g. `save`
  on angr) — distinct from a real error so scripts can branch on it. Use
  `&&` safely.
- **Stripped binaries**: use `list_functions` before `decompile` to find
  the real entry. `main` may not exist; look for non-default names
  (`sub_XXXX`, `FUN_...`, `entry`, etc.) with plausible sizes and xrefs.
- **Backend main-naming varies**: angr promotes the entry to `main`,
  Ghidra leaves `FUN_00101c5c`, IDA emits `sub_101c5c`. Always resolve via
  `list_functions` or a known entry address, not by assuming `main`.
- **Invalid addresses** fail with a clear message distinguishing "no
  function starts here" from "decompiler engine failed". The CLI does not
  auto-round-trip invalid addresses.
- **Address formats**: `0x71d`, `0x40071d`, and `1821` all resolve the
  same function in fauxware. Names are also accepted wherever an address
  is.
- **Servers persist** until explicitly stopped (`decompiler stop --all`)
  or the host reboots; `decompiler list` always reflects live processes.
- **Registry path**: `decompiler list --show-registry` prints just the
  directory so you can clean up manually if you ever need to (e.g. after
  a `kill -9`).
- **Project/database files**: by default they live in
  `<user-cache>/declib/projects/<binary>-<hash>/`, not next to the binary.
  Pass `--project-dir <path>` to `load` to override, or `--project-dir ""`
  to restore the legacy "write next to the binary" behavior.

## Library-level API (for Python scripts)

Everything the CLI does is also available as a library:

```python
from declib.api.decompiler_client import DecompilerClient

client = DecompilerClient.discover_from_registry(binary_path="./fauxware")
for addr, func in client.functions.items():
    if func.name == "main":
        print(client.decompile(addr).text)
```

The new core APIs (`list_strings(filter=...)`, `get_callers(target)`,
`disassemble(addr)`, `read_memory(addr, size)`) are on both the local
`DecompilerInterface` and the `DecompilerClient` proxy. `read_memory`
returns `bytes` (or `None` if the backend can't satisfy the read), so
you can hexdump, decode, or feed the result straight into struct
parsers without going through the CLI.
