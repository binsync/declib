import re
import logging
from collections import OrderedDict, defaultdict, ChainMap
from typing import Optional

import pycparser
from pycparser import c_ast
from pycparser.c_parser import ParseError

# pycparser hack to parse type expressions
errorlog = logging.getLogger(name=__name__ + ".yacc")
errorlog.setLevel(logging.ERROR)


l = logging.getLogger(__name__)


def _patch_pycparser():
    """
    Adds a `parse_type_with_name` method to pycparser.CParser that parses a bare
    type expression (like "int *") rather than a full translation unit. pycparser
    3.0 removed the ability to customize the start production via ply.yacc.
    """
    if hasattr(pycparser.CParser, "parse_type_with_name"):
        return

    def parse_type_with_name(self, text, filename="", scope_stack=None) -> c_ast.Typename:
        self.clex._filename = filename
        self.clex._lineno = 1
        self._scope_stack = [{}] if scope_stack is None else scope_stack

        self.clex.input(text, filename)
        self._tokens = pycparser.c_parser._TokenStream(self.clex)

        return self._parse_type_name()

    pycparser.CParser.parse_type_with_name = parse_type_with_name


_patch_pycparser()


class CType:
    def __init__(
        self,
        type_=None,
        size=0,
        is_primitive=True,
        is_array=False,
        is_ptr=False,
        is_unknown=False
    ):
        self.type = type_
        self._size = size

        self.is_primitive = is_primitive
        self.is_array = is_array
        self.is_ptr = is_ptr
        self.is_unknown = is_unknown

    def __str__(self):
        return f"<{self.__class__.__name__}: {self.type} {'[]' if self.is_array else ''}{'*' if self.is_ptr else ''}" \
               f"{'U' if self.is_unknown else ''} ({self._size})>"

    def __repr__(self):
        return self.__str__()

    @property
    def type_str(self):
        if isinstance(self.type, CType) and self.is_array:
            return self.type.type_str + f"[{self._size}]"

        return self.type

    @property
    def base_type(self):
        if isinstance(self.type, str):
            return self
        elif isinstance(self.type, CType):
            return self.type.base_type

        return self.type

    @property
    def size(self):
        if isinstance(self.type, CType) and self.is_array:
            return self.type.size * self._size

        return self._size


class CTypeParser:
    """
    Most of this code is ripped from angr's sim_type:
    https://github.com/angr/angr/blob/master/angr/sim_type.py

    It is highly simplified and drops a lot of support for real declaration parsing (like a struct dec).
    Instead, we just use it to parse types.
    """
    def __init__(
        self,
        sizeof_ptr=8,
        sizeof_long=8,
        sizeof_double=8,
        sizeof_int=4,
        sizeof_float=4,
        sizeof_short=2,
        sizeof_char=1,
        sizeof_bool=1,
        extra_types=None
    ):
        # sizes
        self.sizeof_ptr = sizeof_ptr
        self.sizeof_long = sizeof_long
        self.sizeof_double = sizeof_double
        self.sizeof_int = sizeof_int
        self.sizeof_float = sizeof_float
        self.sizeof_short = sizeof_short
        self.sizeof_char = sizeof_char
        self.sizeof_bool = sizeof_bool

        # hack in type parsing
        self._type_parser_singleton = pycparser.CParser()
        self.ALL_TYPES = {}
        self.BASIC_TYPES = {}
        self.STDINT_TYPES = {}
        self.extra_types = extra_types or {}
        self.SIZE_TO_TYPES = {}
        self._init_all_types()

    def _init_all_types(self):
        self.BASIC_TYPES = {
            "char": CType(type_="char", size=self.sizeof_char),
            "signed char": CType(type_="signed char", size=self.sizeof_char),
            "unsigned char": CType(type_="unsigned char", size=self.sizeof_char),
            "short": CType(type_="short", size=self.sizeof_short),
            "signed short": CType(type_="signed short", size=self.sizeof_short),
            "unsigned short": CType(type_="unsigned short", size=self.sizeof_short),
            "short int": CType(type_="short int", size=self.sizeof_short),
            "signed short int": CType(type_="signed short int", size=self.sizeof_short),
            "unsigned short int": CType(type_="unsigned short int", size=self.sizeof_short),
            "int": CType(type_="int", size=self.sizeof_int),
            "signed": CType(type_="signed", size=self.sizeof_int),
            "unsigned": CType(type_="unsigned", size=self.sizeof_int),
            "signed int": CType(type_="signed int", size=self.sizeof_int),
            "unsigned int": CType(type_="unsigned int", size=self.sizeof_int),
            "long": CType(type_="long", size=self.sizeof_long),
            "signed long": CType(type_="signed long", size=self.sizeof_long),
            "long signed": CType(type_="long signed", size=self.sizeof_long),
            "unsigned long": CType(type_="unsigned long", size=self.sizeof_long),
            "long int": CType(type_="long int", size=self.sizeof_long),
            "signed long int": CType(type_="signed long int", size=self.sizeof_long),
            "unsigned long int": CType(type_="unsigned long int", size=self.sizeof_long),
            "long unsigned int": CType(type_="long unsigned int", size=self.sizeof_long),
            "long long": CType(type_="long long", size=self.sizeof_long),
            "signed long long": CType(type_="signed long long", size=self.sizeof_long),
            "unsigned long long": CType(type_="unsigned long long", size=self.sizeof_long),
            "long long int": CType(type_="long long int", size=self.sizeof_long),
            "signed long long int": CType(type_="signed long long int", size=self.sizeof_long),
            "unsigned long long int": CType(type_="unsigned long long int", size=self.sizeof_long),
            "__int128": CType(type_="__int128", size=16),
            "unsigned __int128": CType(type_="unsigned __int128", size=16),
            "__int256": CType(type_="__int256", size=32),
            "unsigned __int256": CType(type_="unsigned __int256", size=32),
            "bool": CType(type_="bool", size=self.sizeof_bool),
            "_Bool": CType(type_="_Bool", size=self.sizeof_bool),
            "float": CType(type_="float", size=self.sizeof_float),
            "double": CType(type_="double", size=self.sizeof_double),
            "long double": CType(type_="double", size=self.sizeof_double),
            "void": CType(type_="void", size=self.sizeof_ptr),
        }
        self.ALL_TYPES.update(self.BASIC_TYPES)

        self.STDINT_TYPES = {
            "int8_t": CType(type_="int8_t", size=1),
            "uint8_t": CType(type_="uint8_t", size=1),
            "byte": CType(type_="byte", size=1),
            "int16_t": CType(type_="int16_t", size=2),
            "uint16_t": CType(type_="uint16_t", size=2),
            "word": CType(type_="word", size=2),
            "int32_t": CType(type_="int32_t", size=4),
            "uint32_t": CType(type_="uint32_t", size=4),
            "dword": CType(type_="dword", size=4),
            "int64_t": CType(type_="int64_t", size=8),
            "uint64_t": CType(type_="uint64_t", size=8),
        }
        self.ALL_TYPES.update(self.STDINT_TYPES)
        self.ALL_TYPES.update(self.extra_types)

        for name, ctype in self.ALL_TYPES.items():
            if name.startswith("unsigned"):
                self.SIZE_TO_TYPES[ctype.size] = ctype

    def extract_type_name(self, type_str: str) -> str | None:
        """
        Normalizes types that may come in as declarations, removing any extraneous information that may be present
        and just getting the name of that type.

        In the case of:
        "char *" that would return "char *"
        "struct foo *" that would return "foo *"
        "typedef int my_type" that would return "my_type"
        """
        # XXX: this could be subverted by a type name that contains a scope or external ref ("extern")
        is_defined = any(type_str.strip().startswith(t) for t in ["struct", "enum", "union", "typedef"])
        if not is_defined:
            return type_str

        parsable_type = type_str.replace(";", "").strip()
        type_name = None
        try:
            ast = self._type_parser_singleton.parse(text=parsable_type + ";")
            if ast.ext:
                type_name = ast.ext[0].name
        except ParseError:
            pass

        if type_name is None:
            # do a hackish parse to get the type name, which may be inside a defined type-in-place
            # remove "struct", "enum", "union", and "typedef" keywords, select the final type
            if any(parsable_type.startswith(t) for t in ["struct", "enum", "union", "typedef"]):
                final_type = type_str.split(" ")[-1]
                final_type = final_type.replace(";", "").strip()
                if " " not in final_type:
                    # final sanity check that it really is just a name
                    type_name = final_type

        return type_name

    def parse_type(self, defn, predefined_types=None, arch=None) -> Optional[CType]:  # pylint:disable=unused-argument
        """
        Parse a simple type expression into a SimType

        >>> self.parse_type('int *')
        """
        return self.parse_type_with_name(defn, predefined_types=predefined_types, arch=arch)[0]

    def parse_type_with_name(self, defn, predefined_types=None, arch=None):  # pylint:disable=unused-argument
        """
        Parse a simple type expression into a SimType, returning the a tuple of the type object and any associated name
        that might be found in the place a name would go in a type declaration.

        >>> self.parse_type_with_name('int *foo')
        """
        if not defn:
            return None

        if pycparser is None:
            raise ImportError("Please install pycparser in order to parse C definitions")

        defn = re.sub(r"/\*.*?\*/", r"", defn, flags=re.DOTALL)
        defn = re.sub(r"//.*?$", r"", defn, flags=re.MULTILINE)

        failed_parse = False
        try:
            node = self._type_parser_singleton.parse_type_with_name(text=defn)
        except ParseError:
            failed_parse = True

        #
        # in the event of a failed type parse it may just be a custom type, so we should try again
        # with the struct specifier and see if it works out
        #
        if failed_parse:
            try:
                node = self._type_parser_singleton.parse_type_with_name(text="struct " + defn)
            except Exception:
                return (None, )

        if not isinstance(node, pycparser.c_ast.Typename) and \
                not isinstance(node, pycparser.c_ast.Decl):
            raise pycparser.c_parser.ParseError("Got an unexpected type out of pycparser")

        decl = node.type
        extra_types = {} if not predefined_types else dict(predefined_types)
        return self._decl_to_type(decl, extra_types=extra_types), node.name

    def _decl_to_type(self, decl, extra_types=None) -> Optional[CType]:
        if not decl:
            return decl

        if extra_types is None: extra_types = {}

        if isinstance(decl, pycparser.c_ast.FuncDecl):
            return None

        elif isinstance(decl, pycparser.c_ast.TypeDecl):
            return self._decl_to_type(decl.type, extra_types)

        elif isinstance(decl, pycparser.c_ast.Typedef):
            return self._decl_to_type(decl.type, extra_types)

        elif isinstance(decl, pycparser.c_ast.PtrDecl):
            pts_to = self._decl_to_type(decl.type, extra_types)
            if not pts_to:
                return None

            return CType(type_=pts_to.type, size=self.sizeof_ptr, is_ptr=True, is_unknown=pts_to.is_unknown)

        elif isinstance(decl, pycparser.c_ast.ArrayDecl):
            elem_type = self._decl_to_type(decl.type, extra_types)

            if decl.dim is None:
                """
                r = SimTypeArray(elem_type)
                r._arch = arch
                return r
                """
                return CType(type_=elem_type, is_array=True, size=0)
            try:
                size = self._parse_const(decl.dim, extra_types=extra_types)
            except ValueError as e:
                #l.warning("Got error parsing array dimension, defaulting to zero: %s", e)
                size = 0
            """
            r = SimTypeFixedSizeArray(elem_type, size)
            r._arch = arch
            """
            return CType(type_=elem_type, is_array=True, size=size)

        elif isinstance(decl, pycparser.c_ast.Struct):
            if decl is None:
                return None

            return CType(type_=decl.name, is_unknown=True)

        elif isinstance(decl, pycparser.c_ast.Union):
            return None

        elif isinstance(decl, pycparser.c_ast.IdentifierType):
            key = ' '.join(decl.names)
            if key in extra_types:
                return extra_types[key]
            elif key in self.ALL_TYPES:
                return self.ALL_TYPES[key]
            else:
                #raise TypeError("Unknown type '%s'" % key)
                return CType(type_=key, is_unknown=True)

        elif isinstance(decl, pycparser.c_ast.Enum):
            # See C99 at 6.7.2.2
            return self.ALL_TYPES['int']

        raise ValueError("Unknown type!")

    def _make_scope(self, predefined_types=None):
        """
        Generate CParser scope_stack argument to parse method
        """
        all_types = ChainMap(predefined_types or {}, self.ALL_TYPES)
        scope = dict()
        for ty in all_types:
            if ty in self.BASIC_TYPES:
                continue
            if ' ' in ty:
                continue

            typ = all_types[ty]
            scope[ty] = True
        return [scope]

    def _parse_const(self, c, extra_types=None):
        if type(c) is pycparser.c_ast.Constant:
            return int(c.value, base=0)
        elif type(c) is pycparser.c_ast.BinaryOp:
            if c.op == '+':
                return self._parse_const(c.children()[0][1], extra_types=extra_types) + self._parse_const(
                    c.children()[1][1], extra_types=extra_types)
            if c.op == '-':
                return self._parse_const(c.children()[0][1], extra_types=extra_types) - self._parse_const(
                    c.children()[1][1], extra_types=extra_types)
            if c.op == '*':
                return self._parse_const(c.children()[0][1], extra_types=extra_types) * self._parse_const(
                    c.children()[1][1], extra_types=extra_types)
            if c.op == '/':
                return self._parse_const(c.children()[0][1], extra_types=extra_types) // self._parse_const(
                    c.children()[1][1], extra_types=extra_types)
            if c.op == '<<':
                return self._parse_const(c.children()[0][1], extra_types=extra_types) << self._parse_const(
                    c.children()[1][1], extra_types=extra_types)
            if c.op == '>>':
                return self._parse_const(c.children()[0][1], extra_types=extra_types) >> self._parse_const(
                    c.children()[1][1], extra_types=extra_types)
            raise ValueError('Binary op %s' % c.op)
        elif type(c) is pycparser.c_ast.UnaryOp:
            if c.op == 'sizeof':
                return self._decl_to_type(c.expr.type, extra_types=extra_types).size
            else:
                raise ValueError("Unary op %s" % c.op)
        elif type(c) is pycparser.c_ast.Cast:
            return self._parse_const(c.expr, extra_types=extra_types)
        else:
            raise ValueError(c)

    def size_to_type(self, size: int) -> CType:
        if not size:
            raise ValueError("A type size must be greater than 0")

        ctype = self.SIZE_TO_TYPES.get(size, None)
        if ctype is None:
            # one of two possible things have happend here:
            # 1. this is a type that is larger than the simple types, in which case it's an array
            # 2. this is a type with a non-aligned size, in which case we default to an array as well
            array_size = size // self.sizeof_char
            ctype = self.parse_type(f"char[{array_size}]")
            if ctype is None:
                raise RuntimeError(f"Failed to create a CType of array size {array_size}")

        return ctype