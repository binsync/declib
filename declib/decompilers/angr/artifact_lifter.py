import typing

from declib.api import ArtifactLifter

if typing.TYPE_CHECKING:
    from .interface import AngrInterface

class AngrArtifactLifter(ArtifactLifter):
    """
    TODO: finish me
    """
    def __init__(self, interface: "AngrInterface"):
        super(AngrArtifactLifter, self).__init__(interface)

    def is_arm(self) -> bool:
        if self.deci.binary_arch is not None:
            return "ARM" in self.deci.binary_arch
        return False


    def lift_type(self, type_str: str) -> str:
        return type_str

    def lift_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset

    def lower_type(self, type_str: str) -> str:
        return type_str

    def lower_stack_offset(self, offset: int, func_addr: int) -> int:
        return offset

    def lower_addr(self, addr: int) -> int:
        new_addr = super().lower_addr(addr)
        if self.is_arm() and not self.deci.addr_starts_instruction(addr):
            new_addr += 1

        return new_addr


    def lift_addr(self, addr: int) -> int:
        new_addr = super().lift_addr(addr)
        if self.is_arm() and new_addr % 2 == 1:
            new_addr -= 1

        return new_addr