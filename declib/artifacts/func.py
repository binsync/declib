from typing import Dict, Optional

from .artifact import Artifact
from .stack_variable import StackVariable


#
# Function Header Classes
#

class FunctionArgument(Artifact):
    __slots__ = Artifact.__slots__ + (
        "offset",
        "name",
        "type",
        "size",
    )

    def __init__(
        self,
        offset: int = None,
        name: str = None,
        type_: str = None,
        size: int = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.offset = offset
        self.name = name
        self.type = type_
        self.size = size

    def __str__(self):
        return f"<FuncArg: {self.type} {self.name}; @{self.offset}>"


class FunctionHeader(Artifact):
    __slots__ = Artifact.__slots__ + (
        "name",
        "addr",
        "type",
        "args"
    )

    def __init__(
        self,
        name: str = None,
        addr: int = None,
        type_: str = None,
        args: Optional[Dict[int, FunctionArgument]] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.name = name
        self.addr = addr
        self.type = type_
        self.args: Dict = args or {}

    def __str__(self):
        return f"<FuncHeader: {self.type} {self.name}(args={len(self.args or {})}); @{hex(self.addr)}>"

    def __getstate__(self):
        data_dict = super().__getstate__()
        args_dict = data_dict["args"]
        if args_dict is None:
            return data_dict

        new_args_dict = {hex(k): v.__getstate__() for k, v in args_dict.items()}
        data_dict["args"] = new_args_dict
        return data_dict

    def __setstate__(self, state):
        # Pop nested object data and reconstruct in local variable
        args_dict = state.pop("args", {})
        new_args_dict = {}
        for k, v in args_dict.items():
            fa = FunctionArgument()
            fa.__setstate__(v)
            new_args_dict[int(k, 0)] = fa

        # Put reconstructed objects back in state
        state["args"] = new_args_dict

        # Let super set all attributes at once
        super().__setstate__(state)

    def diff(self, other, **kwargs) -> Dict:
        diff_dict = {}
        # early exit if the two do not match type
        if not isinstance(other, FunctionHeader):
            for k in ["name", "addr", "type"]:
                diff_dict[k] = {
                    "before": getattr(self, k),
                    "after": None
                }

            diff_dict["args"] = {idx: arg.diff(None) for idx, arg in self.args.items()}
            return diff_dict

        # metadata
        for k in ["name", "addr", "type"]:
            if getattr(self, k) == getattr(other, k):
                continue

            diff_dict[k] = {
                "before": getattr(self, k),
                "after": getattr(other, k)
            }

        # args
        diff_dict["args"] = {}
        for idx, self_arg in self.args.items():
            try:
                other_arg = other.args[idx]
            except KeyError:
                other_arg = None

            diff_dict["args"][idx] = self_arg.diff(other_arg)

        for idx, other_arg in other.args.items():
            if idx in diff_dict["args"]:
                continue

            diff_dict["args"][idx] = self.invert_diff(other_arg.diff(None))

        return diff_dict

    def reset_last_change(self):
        if self.args:
            for arg in self.args.values():
                arg.reset_last_change()

    def overwrite_merge(self, obj2: "Artifact", **kwargs):
        fh2: "FunctionHeader" = obj2
        merged_fh: "FunctionHeader" = self.copy()
        if not fh2 or not isinstance(fh2, FunctionHeader) or self == fh2:
            return merged_fh

        if fh2.name is not None:
            merged_fh.name = fh2.name
        if fh2.type is not None:
            merged_fh.type = fh2.type

        # header args
        for off, var in fh2.args.items():
            if var is not None:
                if off in merged_fh.args:
                    merged_var = merged_fh.args[off].overwrite_merge(var)
                else:
                    merged_var = var

                merged_fh.args[off] = merged_var

        return merged_fh

    def nonconflict_merge(self, fh2: "FunctionHeader", **kwargs):
        fh1: "FunctionHeader" = self.copy()
        if not fh2 or not isinstance(fh2, FunctionHeader):
            return fh1

        if fh1.name is None:
            fh1.name = fh2.name

        if fh1.type is None:
            fh1.type = fh2.type

        # header args
        for off, var in fh2.args.items():
            merge_var: FunctionArgument = fh1.args[off].copy() if off in fh1.args else var
            merge_var = merge_var.nonconflict_merge(var)
            fh1.args[off] = merge_var

        return fh1


#
# Full Function Class
#

class Function(Artifact):
    """
    The Function class describes a Function found a decompiler. There are three components to a function:
    1. Metadata
    2. Header
    3. Stack Vars

    The metadata contains info on changes and size. The header holds the return type,
    and arguments (including their types). The stack vars contain StackVariables.
    """

    __slots__ = Artifact.__slots__ + (
        "addr",
        "size",
        "header",
        "stack_vars",
        "dec_obj",
    )

    def __init__(
        self,
        addr: int = None,
        size: int = None,
        header: Optional[FunctionHeader] = None,
        stack_vars: Optional[Dict[int, StackVariable]] = None,
        dec_obj: Optional[object] = None,
        name: str = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        # never use dec_obj for comparison, dumping, etc.
        self._attr_ignore_set.add("dec_obj")

        self.addr = addr
        self.size = size
        self.header = header
        if name is not None:
            self.name = name
        self.stack_vars: Dict[int, StackVariable] = stack_vars or {}

        # a special property which can only be set while running inside the decompiler.
        # contains a reference to the decompiler object associated with this function.
        self.dec_obj = dec_obj

    def __str__(self):
        if self.header:
            return f"<Function: {self.header.type} {self.name}(args={len(self.args)}); @{hex(self.addr)} " \
                   f"vars={len(self.stack_vars)} len={hex(self.size)}>"

        return f"<Function: @{hex(self.addr)} len={hex(self.size)}>"

    def __getstate__(self):
        header = self.header.__getstate__() if self.header else None
        stack_vars = {
            hex(offset): stack_var.__getstate__() for offset, stack_var in self.stack_vars.items()
        } if self.stack_vars else None

        state = super().__getstate__()
        # give alias for name and type for convenience
        state["name"] = self.name
        state["type"] = self.type
        state["header"] = header
        state["stack_vars"] = stack_vars
        return state

    def __setstate__(self, state):
        # When pickle calls __setstate__, __init__ is never called
        # Initialize _attr_ignore_set and add dec_obj to it (as done in __init__)
        if not hasattr(self, '_attr_ignore_set'):
            self._attr_ignore_set = set()
        self._attr_ignore_set.add("dec_obj")

        # XXX: this is a backport of the old state format. Remove this after a few releases.
        if "metadata" in state:
            metadata: Dict = state.pop("metadata")
            metadata.update(state)
            state = metadata

        # Pop nested object data and reconstruct in local variables
        header_dat = state.pop("header", None)
        if header_dat:
            header = FunctionHeader()
            header.__setstate__(header_dat)
        else:
            header = None

        # Handle name/type aliases that override header values
        # We modify the header object directly instead of using property setters
        # to avoid accessing self.header and self.addr before they're initialized
        name_override = state.pop("name", None)
        type_override = state.pop("type", None)

        if name_override is not None and header is not None:
            header.name = name_override
        if type_override is not None and header is not None:
            header.type = type_override

        stack_vars_dat = state.pop("stack_vars", {})
        stack_vars = {}
        if stack_vars_dat:
            for off, stack_var in stack_vars_dat.items():
                sv = StackVariable()
                sv.__setstate__(stack_var)
                stack_vars[int(off, 0)] = sv

        # Put reconstructed objects back in state
        state["header"] = header
        state["stack_vars"] = stack_vars

        # Let super set all attributes at once
        super().__setstate__(state)

        # dec_obj is intentionally excluded from serialization (it's in
        # _attr_ignore_set), so it is never present in `state`. Because Function
        # uses __slots__, the attribute would otherwise be unset after a
        # deserialization round-trip and any access to `func.dec_obj` (e.g. in
        # get_dependencies or a backend's rename path) would raise AttributeError.
        if not hasattr(self, "dec_obj"):
            self.dec_obj = None

    def diff(self, other, **kwargs) -> Dict:
        diff_dict = {}
        if not isinstance(other, Function):
            # metadata
            for k in ["addr", "size"]:
                diff_dict[k] = {
                    "before": getattr(self, k),
                    "after": None
                }

            # header
            diff_dict["header"] = self.header.diff(other.header)
            # args
            diff_dict["stack_vars"] = {off: var.diff(None) for off, var in self.stack_vars.items()}
            return diff_dict

        # metadata
        for k in ["addr", "size"]:
            if getattr(self, k) == getattr(other, k):
                continue

            diff_dict[k] = {
                "before": getattr(self, k),
                "after": getattr(other, k)
            }

        # header
        if self.header:
            diff_dict["header"] = self.header.diff(other.header)
        elif other.header:
            diff_dict["header"] = self.invert_diff(other.header.diff(None))
        else:
            diff_dict["header"] = {"before": None, "after": None}

        # stack vars
        diff_dict["stack_vars"] = {}
        for off, self_var in self.stack_vars.items():
            try:
                other_var = other.stack_vars[off]
            except KeyError:
                other_var = None

            diff_dict["stack_vars"][off] = self_var.diff(other_var)

        for off, other_var in other.stack_vars.items():
            if off in diff_dict["stack_vars"]:
                continue

            diff_dict["stack_vars"][off] = self.invert_diff(other_var.diff(None))

        return diff_dict

    def reset_last_change(self):
        if self.header:
            self.header.reset_last_change()

        if self.stack_vars:
            for sv in self.stack_vars.values():
                sv.reset_last_change()

    def overwrite_merge(self, obj2: "Artifact", **kwargs):
        func2: "Function" = obj2
        merged_func: "Function" = self.copy()
        if not func2 or self == func2:
            return merged_func

        if merged_func.header is None:
            merged_func.header = func2.header.copy() if func2.header else None

        if merged_func.header:
            merged_func.header = merged_func.header.overwrite_merge(func2.header)

            for off, var in func2.stack_vars.items():
                if var is not None:
                    if off in merged_func.stack_vars:
                        merged_var = merged_func.stack_vars[off].overwrite_merge(var)
                    else:
                        merged_var = var

                    merged_func.stack_vars[off] = merged_var

        return merged_func

    def nonconflict_merge(self, func2: "Artifact", **kwargs):
        func1: "Function" = self.copy()

        if not func2 or func1 == func2:
            return func1

        merge_func: "Function" = func1.copy()

        if merge_func.header is None:
            merge_func.header = func2.header.copy() if func2.header else None
        elif func2.header is not None:
            merge_func.header = merge_func.header.nonconflict_merge(func2.header)

        # stack vars
        for off, var in func2.stack_vars.items():
            merge_var = func1.stack_vars[off].copy() if off in func1.stack_vars else var
            merge_var = StackVariable.nonconflict_merge(merge_var, var)

            merge_func.stack_vars[off] = merge_var

        return merge_func

    #
    # Property Shortcuts (Alias)
    #

    @property
    def name(self):
        return self.header.name if self.header else None

    @name.setter
    def name(self, value):
        # create a header if one does not exist for this function
        if not self.header:
            self.header = FunctionHeader(name=None, addr=self.addr)
        self.header.name = value

    @property
    def type(self):
        return self.header.type if self.header else None

    @type.setter
    def type(self, value):
        # create a header if one does not exist for this function
        if not self.header:
            self.header = FunctionHeader(name=None, addr=self.addr)
        self.header.type = value

    @property
    def args(self):
        return self.header.args if self.header else {}
