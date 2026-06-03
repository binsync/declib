import logging

from declib.api import ArtifactLifter
from declib.artifacts import Segment

l = logging.getLogger(name=__name__)

class IDAArtifactLifter(ArtifactLifter):
    lift_map = {
        "__int64": "long long",
        "__int32": "int",
        "__int16": "short",
        "__int8": "char",
        "_BOOL8": "bool",
        "_BOOL4": "bool",
        "_BOOL2": "bool",
        "_BOOL1": "bool",
        "_BOOL": "bool",
        "_BYTE": "char",
        "_WORD": "unsigned short",
        "_DWORD": "unsigned int",
        "_QWORD": "unsigned long long",
    }

    def __init__(self, deci):
        super(IDAArtifactLifter, self).__init__(deci)

    def lift_type(self, type_str: str) -> str:
        return self.lift_ida_type(type_str)

    def lift_stack_offset(self, offset: int, func_addr: int) -> int:
        from . import compat
        return compat.ida_to_bs_stack_offset(func_addr, offset)

    def lower_type(self, type_str: str) -> str:
        # TODO: this is a hack until https://github.com/binsync/declib/issues/97 is solved
        if "/" in type_str:
            type_str = type_str.split("/")[-1]

        return type_str

    def lower_stack_offset(self, offset: int, func_addr: int) -> int:
        from . import compat
        return compat.bs_to_ida_stack_offset(self.lower_addr(func_addr), offset)

    @staticmethod
    def lift_ida_type(type_str: str) -> str:
        for ida_t, bs_t in IDAArtifactLifter.lift_map.items():
            type_str = type_str.replace(ida_t, bs_t)

        return type_str