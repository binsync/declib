import typing

from toml import TomlEncoder

if typing.TYPE_CHECKING:
    from ..api import CTypeParser, CType


class ArtifactFormat:
    TOML = "toml"
    JSON = "json"
    C_LANG = "c"


class TomlHexEncoder(TomlEncoder):
    def __init__(self, _dict=dict, preserve=False):
        super(TomlHexEncoder, self).__init__(_dict, preserve=preserve)
        self.dump_funcs[int] = lambda v: hex(v) if v >= 0 else v


def ctype_from_size(size, type_parser: typing.Optional["CTypeParser"] = None) -> "CType":
    if type_parser is None:
        from ..api.type_parser import CTypeParser
        type_parser = CTypeParser()

    ctype = type_parser.size_to_type(size)
    return ctype
