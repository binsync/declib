from typing import Optional

import toml

from .artifact import Artifact


class GlobalVariable(Artifact):
    __slots__ = Artifact.__slots__ + (
        "addr",
        "name",
        "type",
        "size"
    )

    def __init__(
        self,
        addr: int = None,
        name: str = None,
        type_: Optional[str] = None,
        size: int = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.addr = addr
        self.name = name
        self.type = type_
        self.size = size

    def __str__(self):
        return f"<GlobalVar: {self.type} {self.name}; @{self.addr} len={self.size}>"
