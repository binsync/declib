"""Parsing and formatting of C function prototypes.

Shared by the CLI (``signature`` command) and the DecompilerInterface's
``set_function_signature`` so both agree on how a prototype string maps to a
return type + argument (type, name) pairs.
"""
import re
from typing import List, Optional, Tuple


def split_c_args(body: str) -> List[str]:
    """Split a C argument list on top-level commas (respecting () <> [] nesting)."""
    parts, depth, cur = [], 0, ""
    for ch in body:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def norm_c_type(t: str) -> str:
    """Normalize whitespace and pointer spacing in a C type string."""
    return re.sub(r"\s+", " ", t.replace("*", " * ")).replace(" * ", " *").strip()


def parse_prototype(proto: str) -> Tuple[str, List[Tuple[str, Optional[str]]]]:
    """Parse ``ret name(argtype argname, ...)`` -> (return_type, [(type, name), ...]).

    Handles pointer return/argument types, ``void`` argument lists, and varargs
    (``...``). Argument names are optional. Raises ``ValueError`` on malformed
    input.
    """
    proto = proto.strip().rstrip(";").strip()
    open_i = proto.find("(")
    if open_i == -1:
        raise ValueError("no argument list '(...)' found")
    close_i = proto.rfind(")")
    head = proto[:open_i].strip()
    body = proto[open_i + 1:close_i].strip()

    m = re.search(r"[A-Za-z_]\w*\s*$", head)
    if not m:
        raise ValueError(f"cannot find a function name in {head!r}")
    ret_type = head[:m.start()].strip()
    if not ret_type:
        raise ValueError("missing return type")

    args: List[Tuple[str, Optional[str]]] = []
    if body and body != "void":
        for raw in split_c_args(body):
            raw = raw.strip()
            if raw == "...":
                args.append(("...", None))
                continue
            am = re.search(r"[A-Za-z_]\w*\s*$", raw)
            if am and not raw.endswith("*"):
                aname = am.group().strip()
                atype = raw[:am.start()].strip()
                if not atype:  # bare type, no name (e.g. "int")
                    atype, aname = raw, None
            else:
                atype, aname = raw, None
            args.append((norm_c_type(atype), aname))
    return norm_c_type(ret_type), args


def format_prototype(header) -> str:
    """Render a declib FunctionHeader as a C prototype string."""
    ret = header.type or "void"
    name = header.name or "sub"
    parts = []
    for _off, arg in sorted(header.args.items()):
        atype = arg.type or "int"
        aname = arg.name or ""
        if not aname:
            parts.append(atype)
        else:
            # Glue a pointer type to the name: "char *" + "b" -> "char *b".
            sep = "" if atype.endswith("*") else " "
            parts.append(f"{atype}{sep}{aname}")
    arg_str = ", ".join(parts) if parts else "void"
    ret_sep = "" if ret.endswith("*") else " "
    return f"{ret}{ret_sep}{name}({arg_str})"
