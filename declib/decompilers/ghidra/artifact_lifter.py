import logging
import typing

from declib.api import ArtifactLifter

_l = logging.getLogger(name=__name__)

if typing.TYPE_CHECKING:
    from .interface import GhidraDecompilerInterface


class GhidraArtifactLifter(ArtifactLifter):
    lift_map = {
        "undefined64": "long long",
        "undefined32": "int",
        "undefined16": "short",
        "undefined8": "char",
        "undefined": "char",
        "char8": "char[8]",
        "char4": "char[4]",
        "char2": "char[2]",
        "char1": "char",
        #"sqword": "long long",
        #"qword": "long long",
        #"sdword": "int",
        #"dword": "int",
        #"word": "short",
        #"byte": "char",
    }

    def lift_type(self, type_str: str) -> str:
        og_type_str = type_str
        # convert to simple C when possible
        for ghidra_t, bs_t in self.lift_map.items():
            type_str = type_str.replace(ghidra_t, bs_t)

        # parse out type decls if needed
        type_str = self.type_parser.extract_type_name(type_str)
        if type_str is None:
            self.deci.error(f"Failed to extract type name from {og_type_str}, defaulting to void *")
            type_str = "void *"

        scope_count = type_str.count("/")
        if scope_count:
            name, scope = self.deci._gscoped_type_to_bs(type_str)
            type_str = self.scoped_type_to_str(name, scope=scope)

        return type_str

    def lift_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset

    def lower_type(self, type_str: str) -> str:
        if self.SCOPE_DELIMITER in type_str:
            type_str = self.deci._bs_scoped_type_to_g(type_str)

        return type_str

    def lower_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset
