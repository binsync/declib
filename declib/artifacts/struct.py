from typing import Dict, List, Optional

import toml

from .artifact import Artifact
from . import TomlHexEncoder

import logging
l = logging.getLogger(name=__name__)


class StructMember(Artifact):
    """
    Describes a struct member that corresponds to a struct.
    Offset is the byte offset of the member from the start of the struct.
    """

    __slots__ = Artifact.__slots__ + (
        "name",
        "offset",
        "type",
        "size",
    )

    def __init__(
        self,
        name: str = None,
        offset: int = None,
        type_: Optional[str] = None,
        size: int = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.name: str = name
        self.offset: int = offset
        self.type: str = type_
        self.size: int = size

    def __str__(self):
        return f"<StructMember: {self.type} {self.name}; @{hex(self.offset)}>"


class Struct(Artifact):
    """
    Describes a struct.
    All members are stored by their byte offset from the start of the struct.
    """

    __slots__ = Artifact.__slots__ + (
        "name",
        "size",
        "members",
    )

    def __init__(
        self,
        name: str = None,
        size: int = None,
        members: Dict[int, StructMember] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.name = name
        self.size = size or 0
        self.members: Dict[int, StructMember] = members or {}

    def __str__(self):
        scope_str = f" scope={self.scope}" if self.scope else ""
        return f"<Struct: {self.name} membs={len(self.members)}{scope_str} ({hex(self.size)})>"

    def __getstate__(self):
        data_dict = super().__getstate__()
        data_dict["members"] = {
            hex(offset): member.__getstate__() for offset, member in self.members.items()
        }

        return data_dict

    def __setstate__(self, state):
        # XXX: this is a backport of the old state format. Remove this after a few releases.
        if "metadata" in state:
            metadata: Dict = state.pop("metadata")
            metadata.update(state)
            state = metadata

        # Pop nested object data and reconstruct in local variable
        members_dat = state.pop("members", None)
        members = {}
        if members_dat:
            for off, member in members_dat.items():
                sm = StructMember()
                sm.__setstate__(member)
                members[int(off, 0)] = sm

        # Put reconstructed objects back in state
        state["members"] = members

        # Let super set all attributes at once
        super().__setstate__(state)

    def add_struct_member(self, mname, moff, mtype, size):
        self.members[moff] = StructMember(mname, moff, mtype, size)

    def append_struct_member(self, mname, mtype, size):
        # first, find the next available offset
        next_offset = 0
        for off in self.members.keys():
            if off >= next_offset:
                next_offset = off + self.members[off].size
        self.members[next_offset] = StructMember(mname, next_offset, mtype, size)

    def diff(self, other, **kwargs) -> Dict:
        diff_dict = {}
        if not isinstance(other, Struct):
            return diff_dict

        for k in ["name", "size"]:
            if getattr(self, k) == getattr(other, k):
                continue

            diff_dict[k] = {
                "before": getattr(self, k),
                "after": getattr(other, k)
            }

        # struct members
        diff_dict["members"] = {}
        for off, member in self.members.items():
            try:
                other_mem = other.members[off]
            except KeyError:
                other_mem = None

            diff_dict["members"][off] = member.diff(other_mem)

        for off, other_mem in other.members.items():
            if off in diff_dict["members"]:
                continue

            diff_dict["members"][off] = self.invert_diff(other_mem.diff(None))

        return diff_dict

    def nonconflict_merge(self, struct2: "Struct", **kwargs) -> "Struct":
        struct1: "Struct" = self.copy()
        if not struct2 or struct1 == struct2:
            return struct1

        struct_diff = struct1.diff(struct2)
        merge_struct = struct1

        members_diff = struct_diff["members"]
        for off, mem in struct2.members.items():
            # no difference
            if off not in members_diff:
                continue

            mem_diff = members_diff[off]

            # struct member is newly created
            if "before" in mem_diff and mem_diff["before"] is None:
                # check for overlap
                new_mem_size = mem.size
                new_mem_offset = mem.offset

                for off_check in range(new_mem_offset, new_mem_offset + new_mem_size):
                    if off_check in merge_struct.members:
                        break
                else:
                    merge_struct.members[off] = mem.copy()

                continue

            # member differs
            merge_mem = merge_struct.members.get(off, None)
            if not merge_mem:
                merge_mem = mem

            merge_mem = StructMember.nonconflict_merge(merge_mem, mem)
            merge_struct.members[off] = merge_mem

        # compute the new size
        merge_struct.size = sum(mem.size for mem in merge_struct.members.values())
        return merge_struct
