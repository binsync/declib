import toml

from .artifact import Artifact


class StackVariable(Artifact):
    """
    Describes a stack variable for a given function.
    """

    __slots__ = Artifact.__slots__ + (
        "offset",
        "name",
        "type",
        "size",
        "addr",
    )

    def __init__(
        self,
        stack_offset: int = None,
        name: str = None,
        type_: str = None,
        size: int = None,
        addr: int = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.offset = stack_offset
        self.name = name
        self.type = type_
        self.size = size
        self.addr = addr

    def __str__(self):
        return f"<StackVar: {self.type} {self.name}; {hex(self.offset)}@{hex(self.addr)}>"

    @classmethod
    def load_many(cls, svs_toml):
        for sv_toml in svs_toml.values():
            sv = StackVariable(None, None, None, None, None)
            sv.__setstate__(sv_toml)
            yield sv

    @classmethod
    def dump_many(cls, svs):
        d = { }
        for v in sorted(svs.values(), key=lambda x: x.addr):
            d[hex(v.addr)] = v.__getstate__()
        return d
