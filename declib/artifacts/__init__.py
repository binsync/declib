import json

import toml

from .formatting import TomlHexEncoder, ArtifactFormat
from .artifact import Artifact
from .comment import Comment
from .decompilation import Decompilation
from .enum import Enum
from .func import Function, FunctionHeader, FunctionArgument
from .global_variable import GlobalVariable
from .patch import Patch
from .segment import Segment
from .stack_variable import StackVariable
from .struct import Struct, StructMember
from .context import Context
from .typedef import Typedef

ART_NAME_TO_CLS = {
    Function.__name__: Function,
    FunctionHeader.__name__: FunctionHeader,
    FunctionArgument.__name__: FunctionArgument,
    StackVariable.__name__: StackVariable,
    Comment.__name__: Comment,
    GlobalVariable.__name__: GlobalVariable,
    Enum.__name__: Enum,
    Struct.__name__: Struct,
    StructMember.__name__: StructMember,
    Patch.__name__: Patch,
    Decompilation.__name__: Decompilation,
    Context.__name__: Context,
    Typedef.__name__: Typedef,
    Segment.__name__: Segment,
}

ALL_ARTIFACTS = list(ART_NAME_TO_CLS.values())


def _dict_from_str(art_str: str, fmt=ArtifactFormat.TOML) -> dict:
    if fmt == ArtifactFormat.TOML:
        return toml.loads(art_str)
    elif fmt == ArtifactFormat.JSON:
        return json.loads(art_str)
    else:
        raise ValueError(f"Loading from format {fmt} is not yet supported.")


def _art_from_dict(art_dict: dict) -> Artifact:
    art_type_str = art_dict.get(Artifact.ART_TYPE_STR, None)
    if art_type_str is None:
        raise ValueError(f"Artifact type string not found in artifact data: {art_dict}. Is this a valid artifact?")

    art_cls = ART_NAME_TO_CLS[art_type_str]
    art = art_cls()
    art.__setstate__(art_dict)
    return art


def _load_arts_from_list(art_strs: list[str], fmt=ArtifactFormat.TOML) -> list[Artifact]:
    arts = []
    for art_str in art_strs:
        data_dict = _dict_from_str(art_str, fmt=fmt)
        art = _art_from_dict(data_dict)
        arts.append(art)
    return arts


def _load_arts_from_string(art_str: str, fmt=ArtifactFormat.TOML) -> list[Artifact]:
    data_dict = _dict_from_str(art_str, fmt=fmt)
    if isinstance(data_dict, dict):
        data_dicts = list(data_dict.values())
    elif isinstance(data_dict, list):
        data_dicts = data_dict
    else:
        raise ValueError(f"Unexpected data type: {type(data_dict)}")

    arts = []
    for v in data_dicts:
        art = _art_from_dict(v)
        arts.append(art)

    return arts


def load_many_artifacts(art_strings: list[str], fmt=ArtifactFormat.TOML) -> list[Artifact]:
    """
    A helper function to load many dumped artifacts from a list of strings. Each string should have been dumped
    using the `dumps` method of an artifact.

    :param art_strings: A list of strings or a single string containing multiple dumped artifacts.
    :param fmt: The format of the dumped artifacts.
    """
    return _load_arts_from_list(art_strings, fmt=fmt)
