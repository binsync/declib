import toml

from .artifact import Artifact


class Decompilation(Artifact):
    __slots__ = Artifact.__slots__ + (
        "addr",
        "text",
        "line_map",
        "decompiler",
        "bs_func",
    )

    def __init__(
        self,
        addr: int = None,
        text: str = None,
        line_map: dict = None,
        decompiler: str = None,
        bs_func = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.addr = addr
        self.text = text
        self.line_map = line_map or {}
        self.decompiler = decompiler
        self.bs_func = bs_func

    def __str__(self):
        return f"//ADDR: {hex(self.addr)}\n// SOURCE: {self.decompiler}\n{self.text}"

    def __repr__(self):
        return f"<Decompilation: {self.decompiler}@{hex(self.addr)} len={len(self.text)}>"
