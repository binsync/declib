import codecs

import toml

from .artifact import Artifact


class Patch(Artifact):
    """
    Describes a patch on the binary code.
    """
    __slots__ = Artifact.__slots__ + (
        "addr",
        "name",
        "bytes",
    )

    def __init__(
        self,
        addr: int = None,
        bytes_: bytes = None,
        name: str = None,
        **kwargs
    ):
        super(Patch, self).__init__(**kwargs)
        self.addr = addr
        self.name = name
        self.bytes = bytes_

    def __str__(self):
        return f"<Patch: {self.name}@{hex(self.addr)} len={len(self.bytes)}>"

    def __getstate__(self):
        data_dict = super().__getstate__()
        data_dict["bytes"] = codecs.encode(self.bytes, "hex").decode()
        return data_dict

    def __setstate__(self, state):
        # Pop and decode bytes data
        bytes_dat = state.pop("bytes", None)
        decoded_bytes = None
        if bytes_dat:
            decoded_bytes = codecs.decode(bytes_dat, "hex")

        # Put decoded bytes back in state
        state["bytes"] = decoded_bytes

        # Let super set all attributes at once
        super().__setstate__(state)
