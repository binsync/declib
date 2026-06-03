import typing
import logging

from declib.artifacts import (
    Artifact, Comment, Enum, FunctionHeader, Function, FunctionArgument,
    GlobalVariable, Patch, Segment, StackVariable, Struct, StructMember, Typedef
)

if typing.TYPE_CHECKING:
    from declib.api import DecompilerInterface

_l = logging.getLogger(__name__)


class ArtifactDict(dict):
    """
    The ArtifactDict is a Dictionary wrapper around the getting/setting/listing of artifacts in the decompiler. This
    allows for a more pythonic interface to the decompiler artifacts. For example, instead of doing:
    deci._set_function(func)

    You can do:
    >>> deci.functions[func.addr] = func

    This class is not meant to be instantiated directly, but rather through the DecompilerInterface class.
    There is currently some interesting affects and caveats to using this class:
    - When you list artifacts, by calling list(), you will get a light copy of the artifacts. This means that if you
        modify the artifacts in the list, they will not be reflected in the decompiler. You also do need get current
        data in the decompiler, only an acknowledgement that the artifact exists.
    - You must reassign the artifact to the dictionary to update the decompiler.
    - When assigning something to the dictionary, it must always be in its lifted form. You will also only get lifted
        artifacts back from the dictionary.
    - For convience, you can access functions by their lowered address
    """

    def __init__(self, artifact_cls, deci: "DecompilerInterface", error_on_duplicate=False, scopable=False):
        super().__init__()

        self._deci = deci
        self._error_on_duplicate = error_on_duplicate
        self._scopable = scopable
        self._art_function = {
            # ArtifactType: (setter, getter, lister)
            Function: (self._deci._set_function, self._deci._get_function, self._deci._functions, self._deci._del_function),
            StackVariable: (self._deci._set_stack_variable, self._deci._get_stack_variable, self._deci._stack_variables, self._deci._del_stack_variable),
            GlobalVariable: (self._deci._set_global_variable, self._deci._get_global_var, self._deci._global_vars, self._deci._del_global_var),
            Struct: (self._deci._set_struct, self._deci._get_struct, self._deci._structs, self._deci._del_struct),
            Enum: (self._deci._set_enum, self._deci._get_enum, self._deci._enums, self._deci._del_enum),
            Typedef: (self._deci._set_typedef, self._deci._get_typedef, self._deci._typedefs, self._deci._del_typedef),
            Comment: (self._deci._set_comment, self._deci._get_comment, self._deci._comments, self._deci._del_comment),
            Patch: (self._deci._set_patch, self._deci._get_patch, self._deci._patches, self._deci._del_patch),
            Segment: (self._deci._set_segment, self._deci._get_segment, self._deci._segments, self._deci._del_segment)
        }

        functions = self._art_function.get(artifact_cls, None)
        if functions is None:
            raise ValueError(f"Attempting to create a dict for a Artifact class that is not supported: {artifact_cls}")

        self._artifact_class = artifact_cls
        self._artifact_setter, self._artifact_getter, self._artifact_lister, self._artifact_remover = functions

    def __len__(self):
        return len(self._artifact_lister())

    def _lifted_art_lister(self):
        d = self._artifact_lister()
        d_items = list(d.items())
        if not d_items:
            return {}

        is_addr = hasattr(d_items[0][1], "addr")
        new_d = {}
        for k, v in d_items:
            if is_addr:
                k = self._deci.art_lifter.lift_addr(k)
            new_d[k] = self._deci.art_lifter.lift(v)

        return new_d

    def __getitem__(self, item):
        """
        Takes a lifted identifier as input and returns a lifted artifact
        """
        if isinstance(item, int):
            item = self._deci.art_lifter.lower_addr(item)
        if self._scopable and not self._deci.supports_type_scopes:
            item, _ = self._deci.art_lifter.parse_scoped_type(item)

        art = self._artifact_getter(item)
        if art is None:
            raise KeyError

        return self._deci.art_lifter.lift(art)

    def __setitem__(self, key, value):
        """
        Both key and value must be lifted artifacts
        """
        if not isinstance(value, self._artifact_class):
            raise ValueError(f"Attempting to set a value of type {type(value)} to a dict of type {self._artifact_class}")

        if isinstance(key, int):
            key = self._deci.art_lifter.lower_addr(key)
        if self._scopable and not self._deci.supports_type_scopes:
            key, _ = self._deci.art_lifter.parse_scoped_type(key)

        art = self._deci.art_lifter.lower(value)
        if not self._artifact_setter(art) and self._error_on_duplicate:
            raise ValueError(f"Set value {value} is already present at key {key}")

    def __contains__(self, item):
        if isinstance(item, int):
            item = self._deci.art_lifter.lower_addr(item)
        if self._scopable and not self._deci.supports_type_scopes:
            item, _ = self._deci.art_lifter.parse_scoped_type(item)

        data = self._artifact_getter(item)
        return data is not None

    def __delitem__(self, key):
        if isinstance(key, int):
            key = self._deci.art_lifter.lower_addr(key)
        if self._scopable and not self._deci.supports_type_scopes:
            key, _ = self._deci.art_lifter.parse_scoped_type(key)

        art = self._artifact_getter(key)
        if isinstance(art, Struct):
            self._artifact_remover(key)
            self._deci.struct_changed(art, deleted=True)
        else:
            self._artifact_remover(key)

    def __iter__(self):
        return iter(self._lifted_art_lister())

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self._artifact_class.__name__} len={self.__len__()}>"

    def __str__(self):
        return f"{self._lifted_art_lister()}"

    def keys(self):
        return self._lifted_art_lister().keys()

    def values(self):
        return self._lifted_art_lister().values()

    def items(self):
        return self._lifted_art_lister().items()

    def get(self, key, default=None):
        if key in self:
            return self[key]
        return default
