from typing import Optional

from .artifact import Artifact


class Typedef(Artifact):
    """
    Describe a typedef. As an example:
    typedef struct MyStruct {
        int a;
        int b;
    } my_struct_t;

    name="my_struct_t"
    type="MyStruct"

    Another example:
    typedef int my_int_t;

    name="my_int_t"
    type="int"
    """

    __slots__ = Artifact.__slots__ + (
        "name",
        "type",
    )

    def __init__(
        self,
        name: str = None,
        type_: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.name: str = name
        self.type: str = type_

    def __str__(self):
        scope_str = f" scope={self.scope}" if self.scope else ""
        return f"<TypeDef: {self.name}={self.type}{scope_str}>"

    def nonconflict_merge(self, typedef2: "Typedef", **kwargs):
        typedef1: Typedef = self.copy()
        if not typedef2 or typedef1 == typedef2:
            return typedef1.copy()

        master_state = kwargs.get("master_state", None)
        local_names = {typedef1.name}
        if master_state:
            for _, typedef in master_state.get_typedefs().items():
                local_names.add(typedef.name)
        else:
            local_names = {typedef1.name}

        if typedef2.name not in local_names:
            typedef1.name = typedef2.name
            typedef1.type = typedef2.type
        return typedef1
