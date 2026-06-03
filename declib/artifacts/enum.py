from collections import OrderedDict
from typing import Dict

from .artifact import Artifact


class Enum(Artifact):
    __slots__ = Artifact.__slots__ + (
        "name",
        "members",
    )

    def __init__(
        self,
        name: str = None,
        members: Dict[str, int] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.name = name
        # sorts map by the int value
        self.members = self._order_members(members) if members else {}

    def __str__(self):
        scope_str = f" scope={self.scope}" if self.scope else ""
        return f"<Enum: {self.name} member_count={len(self.members)}{scope_str}>"

    @staticmethod
    def _order_members(members):
        return OrderedDict(sorted(members.items(), key=lambda kv: kv[1]))

    def nonconflict_merge(self, enum2: "Enum", **kwargs):
        enum1: Enum = self.copy()
        if not enum2 or enum1 == enum2:
            return enum1.copy()

        master_state = kwargs.get("master_state", None)
        local_names = {mem for mem in enum1.members}
        if master_state:
            for _, enum in master_state.get_enums().items():
                local_names.union(set(enum.members.keys()))
        else:
            local_names = enum1.members

        constants = {
            value for value in enum1.members.values()
        }

        for name, constant in enum2.members.items():
            if name in local_names or constant in constants:
                continue
            enum1.members[name] = constant
        return enum1
