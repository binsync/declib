import textwrap
from typing import Optional

from .artifact import Artifact


class Comment(Artifact):
    __slots__ = Artifact.__slots__ + (
        "addr",
        "func_addr",
        "comment",
        "decompiled",
    )

    def __init__(
        self,
        addr: int = None,
        comment: Optional[str] = None,
        func_addr: int = None,
        decompiled: bool = False,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.addr = addr
        self.comment = self.linewrap_comment(comment) if comment else None
        self.func_addr = func_addr
        self.decompiled = decompiled

    def __str__(self):
        cmt_len = len(self.comment) if self.comment else 0
        return f"<Comment: @{hex(self.addr)} len={cmt_len}>"

    @staticmethod
    def linewrap_comment(comment: str, width=100) -> str:
        # Split the comment into lines based on existing newlines
        lines = comment.split('\n')
        # Wrap each line individually and preserve newlines
        wrapped_lines = [textwrap.fill(line, width=width) for line in lines]
        # Join the wrapped lines with newline characters
        wrapped_text = '\n'.join(wrapped_lines)
        return wrapped_text

    def nonconflict_merge(self, obj2: "Comment", **kwargs) -> "Comment":
        obj1: "Comment" = self.copy()
        if not obj2 or obj1 == obj2:
            return obj1

        merge_comment = obj1
        return merge_comment
