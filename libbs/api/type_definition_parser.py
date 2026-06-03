"""
Parse a single C type *definition* string into the matching libbs artifact.

Unlike ``CTypeParser`` (libbs/api/type_parser.py), which is deliberately scoped to
type *expressions* ("int *", "struct Foo *"), this module handles full type
*definitions* with bodies:

  - ``struct Name { <members> };`` -> :class:`libbs.artifacts.Struct`
  - ``enum Name { A, B=5, C };``    -> :class:`libbs.artifacts.Enum`
  - ``typedef <type> Name;``        -> :class:`libbs.artifacts.Typedef`

It is intentionally decompiler-free and unit-testable: the heavy lifting is done by
``pycparser`` (already a libbs dependency) for the AST and member type-string
rendering, and by ``CTypeParser`` for member sizing. The resulting artifact is then
applied to a decompiler via the normal ``deci.structs[name] = struct`` /
``deci.set_artifact(...)`` path, which is portable across every backend.
"""
import logging
import re
from typing import Optional, Union

import pycparser
from pycparser import c_ast, c_generator
from pycparser.c_parser import ParseError

from libbs.artifacts import Struct, StructMember, Enum, Typedef
from libbs.api.type_parser import CTypeParser

_l = logging.getLogger(__name__)

# Reuse single instances; both are stateless across parses.
_GENERATOR = c_generator.CGenerator()
_PARSER = pycparser.CParser()
_DEFAULT_TYPE_PARSER = CTypeParser()

# Member natural alignment is its own size in System V, capped at the platform
# word width (pointers/long are 8 in CTypeParser's defaults).
_MAX_ALIGN = 8


class TypeDefinitionParseError(ValueError):
    """Raised when a C type-definition string cannot be turned into a libbs artifact."""


def parse_type_definition(
    text: str,
    type_parser: Optional[CTypeParser] = None,
) -> Union[Struct, Enum, Typedef]:
    """
    Parse a single C type *definition* into the matching libbs artifact.

    Supports exactly one top-level definition: a named ``struct``, ``enum``, or
    ``typedef``. Raises :class:`TypeDefinitionParseError` on anything unparseable,
    anonymous, multi-definition, or otherwise unsupported.

    >>> parse_type_definition("struct Point { int x; int y; }")
    <Struct: Point membs=2 (0x8)>
    """
    tp = type_parser or _DEFAULT_TYPE_PARSER
    ast = _parse_ast(_normalize(text))
    top = ast.ext[0]

    if isinstance(top, c_ast.Typedef):
        return _typedef_from_ast(top)

    # struct/enum arrive wrapped in a Decl whose .type is the Struct/Enum node
    if isinstance(top, c_ast.Decl):
        inner = top.type
        if isinstance(inner, c_ast.Struct):
            return _struct_from_ast(inner, tp)
        if isinstance(inner, c_ast.Enum):
            return _enum_from_ast(inner, tp)

    raise TypeDefinitionParseError(
        f"Unsupported top-level definition: {type(top).__name__}. "
        "Expected a named struct, enum, or typedef."
    )


def _normalize(text: str) -> str:
    if not text or not text.strip():
        raise TypeDefinitionParseError("Empty type definition.")
    # strip C comments (same approach as CTypeParser.parse_type_with_name)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
    text = text.strip()
    if not text.endswith(";"):
        text += ";"
    return text


def _parse_ast(text: str) -> c_ast.FileAST:
    try:
        ast = _PARSER.parse(text)
    except ParseError as exc:
        raise TypeDefinitionParseError(f"could not parse C definition: {exc}")
    if not ast.ext:
        raise TypeDefinitionParseError("no type definition found.")
    if len(ast.ext) != 1:
        raise TypeDefinitionParseError(
            "expected exactly one type definition, got "
            f"{len(ast.ext)}. Define one type at a time."
        )
    return ast


def _render_type(node) -> str:
    """Render a member/typedef type node back to a C type string, e.g. "char *"."""
    rendered = _GENERATOR.visit(node).strip()
    if "\n" in rendered or "{" in rendered:
        raise TypeDefinitionParseError(
            "inline/nested type definitions are unsupported here; define the "
            "inner type separately and reference it by name."
        )
    return rendered


def _member_size(tp: CTypeParser, type_str: str) -> int:
    ct = tp.parse_type(type_str)
    if ct is None or not ct.size:
        # Unknown, user-defined non-pointer type (e.g. "struct Bar" before Bar
        # exists): we cannot reliably size it, so reject rather than emit a
        # 0-size member that would corrupt every subsequent offset.
        raise TypeDefinitionParseError(
            f"could not determine the size of member type {type_str!r}. "
            "Define referenced types first, or use a pointer/primitive."
        )
    return ct.size


def _struct_from_ast(struct_node: c_ast.Struct, tp: CTypeParser) -> Struct:
    if not struct_node.name:
        raise TypeDefinitionParseError(
            "anonymous structs are not supported; give the struct a name."
        )
    if not struct_node.decls:
        raise TypeDefinitionParseError(
            f"struct {struct_node.name!r} has no members to define."
        )

    members = {}
    offset = 0
    max_align = 1
    for decl in struct_node.decls:
        if decl.name is None:
            raise TypeDefinitionParseError(
                f"unnamed member in struct {struct_node.name!r} is unsupported."
            )
        type_str = _render_type(decl.type)
        size = _member_size(tp, type_str)
        align = min(size, _MAX_ALIGN) if size else 1
        # round the running offset up to this member's natural alignment
        if align > 1 and offset % align:
            offset += align - (offset % align)
        members[offset] = StructMember(
            name=decl.name, offset=offset, type_=type_str, size=size,
        )
        offset += size
        max_align = max(max_align, align)

    total = offset
    if max_align > 1 and total % max_align:
        total += max_align - (total % max_align)

    return Struct(name=struct_node.name, size=total, members=members)


def _enum_from_ast(enum_node: c_ast.Enum, tp: CTypeParser) -> Enum:
    if not enum_node.name:
        raise TypeDefinitionParseError(
            "anonymous enums are not supported; give the enum a name."
        )
    if not enum_node.values or not enum_node.values.enumerators:
        raise TypeDefinitionParseError(
            f"enum {enum_node.name!r} has no members to define."
        )

    members = {}
    next_val = 0
    for en in enum_node.values.enumerators:
        if en.value is None:
            val = next_val
        else:
            try:
                val = tp._parse_const(en.value)
            except Exception:
                raise TypeDefinitionParseError(
                    f"could not evaluate enum value for {en.name!r}."
                )
        members[en.name] = val
        next_val = val + 1

    return Enum(name=enum_node.name, members=members)


def _typedef_from_ast(typedef_node: c_ast.Typedef) -> Typedef:
    name = typedef_node.name
    if not name:
        raise TypeDefinitionParseError("typedef is missing a name.")
    type_str = _render_type(typedef_node.type)
    return Typedef(name=name, type_=type_str)
