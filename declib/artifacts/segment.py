from typing import Optional

from .artifact import Artifact


class Segment(Artifact):
    __slots__ = Artifact.__slots__ + (
        "name",
        "start_addr", 
        "end_addr",
        "permissions"
    )

    def __init__(
        self,
        name: str = None,
        start_addr: int = None,
        end_addr: int = None,
        permissions: Optional[str] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.name = name
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.permissions = permissions

    def __str__(self):
        perms_str = f" [{self.permissions}]" if self.permissions else ""
        return f"<Segment: {self.name} {hex(self.start_addr) if self.start_addr else '?'}-{hex(self.end_addr) if self.end_addr else '?'}{perms_str}>"

    @property
    def size(self) -> Optional[int]:
        """Returns the size of the segment in bytes."""
        if self.start_addr is not None and self.end_addr is not None:
            return self.end_addr - self.start_addr
        return None