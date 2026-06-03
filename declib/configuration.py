import builtins
from typing import Optional, Dict

from declib.decompilers import SUPPORTED_DECOMPILERS, GHIDRA_DECOMPILER, IDA_DECOMPILER, ANGR_DECOMPILER, \
    BINJA_DECOMPILER
from platformdirs import user_config_dir
from filelock import FileLock
import pathlib
import logging
import toml
import os

_l = logging.getLogger(__name__)


class DLConfig:
    __slots__ = (
        "save_location",
        "_config_lock",
    )

    def __init__(self, save_location: Optional[str] = None):
        if not save_location:
            save_location = user_config_dir("declib")
        self.save_location = _create_path(save_location)
        self._config_lock = FileLock(save_location + f"/{self.__class__.__name__}.lock", timeout=-1)

    def save(self):
        self.save_location = _create_path(self.save_location)
        if not self.save_location.parent.exists():
            self.save_location.parent.mkdir(parents=True, exist_ok=True)

        dump_dict = {}
        for attr in self.__slots__:
            if attr == '_config_lock':
                continue
            attr_val = getattr(self, attr)
            if isinstance(attr_val, pathlib.Path):
                attr_val = str(attr_val)

            if isinstance(attr_val, dict):
                attr_val = {k: str(v) if isinstance(v, pathlib.Path) else v for k, v in attr_val.items()}

            dump_dict[attr] = attr_val

        with self._config_lock:
            with open(self.save_location, "w") as fp:
                toml.dump(dump_dict, fp)

        _l.debug("Saved config to %s", self.save_location)
        return True

    def load(self):
        self.save_location = _create_path(self.save_location)
        if not self.save_location.exists():
            return None

        with self._config_lock:
            with open(self.save_location, "r") as fp:
                load_dict = toml.load(fp)

        for attr in self.__slots__:
            if attr == '_config_lock':
                continue
            setattr(self, attr, load_dict.get(attr, None))

        return self

    @classmethod
    def load_from_file(cls, save_location=None):
        config = cls(save_location)
        return config.load()

    @classmethod
    def update_or_make(cls, save_location=None, **attrs_to_update):
        exists = False
        if save_location:
            save_location = _create_path(save_location)
            exists = save_location.exists()

        if not exists:
            config = cls(save_location)
        else:
            config = cls.load_from_file(save_location)

        for attr, val in attrs_to_update.items():
            if attr in config.__slots__:
                setattr(config, attr, val)

        config.save()
        return config


class DecLibConfig(DLConfig):
    __slots__ = (
        "save_location",
        "plugins_paths",
        "headless_binary_paths",
        "gdbinit_path",
    )

    def __init__(self,
                 save_location: Optional[str] = None,
                 plugins_paths: Optional[Dict] = {},
                 headless_binary_paths: Optional[Dict] = {},
                 gdbinit_path: Optional[str] = None
                 ):
        super().__init__(save_location)
        self.save_location = self.save_location / f"{__class__.__name__}.toml"
        self.gdbinit_path = gdbinit_path
        self.plugins_paths = {}
        self.headless_binary_paths = {}

    @classmethod
    def update_or_make(cls, save_location=None, **attrs_to_update):
        exists = False
        if save_location:
            save_location = _create_path(save_location)
            exists = save_location.exists()

        if not exists:
            config = cls(save_location)
        else:
            config = cls.load_from_file(save_location)

        for attr, val in attrs_to_update.items():
            if attr in config.__slots__:
                setattr(config, attr, val)

        for decompiler in SUPPORTED_DECOMPILERS:
            plugins_path = config.plugins_paths[decompiler] if decompiler in config.plugins_paths else None
            headless_path = config.headless_binary_paths[
                decompiler] if decompiler in config.headless_binary_paths else None
            # Attempt to find default plugins_path if not given
            if not plugins_path:
                plugins_path = _infer_plugins_path(decompiler)
            # Check if only plugins path exists and attempt to infer headless path
            if plugins_path and not headless_path:
                headless_path = _infer_headless_path(plugins_path, decompiler)
            config.plugins_paths[decompiler] = plugins_path
            config.headless_binary_paths[decompiler] = headless_path

        config.save()
        return config


def _create_path(path_str):
    return pathlib.Path(path_str).expanduser().absolute()


def _infer_headless_path(plugins_path, decompiler):
    if decompiler == GHIDRA_DECOMPILER:
        # Infer ghidra headless
        plugins_path = _create_path(plugins_path)
        install_root = plugins_path.parent
        headless_path = install_root / "support" / ("analyzeHeadless.bat" if os.name == 'nt' else "analyzeHeadless")
        return headless_path if headless_path.exists() else None

    if decompiler == IDA_DECOMPILER:
        # Infer ida headless
        plugins_path = _create_path(plugins_path)
        install_root = plugins_path.parent.parent
        headless_path = install_root / "idat64"
        return headless_path if headless_path.exists() else None

    return None


def _infer_plugins_path(decompiler):
    home = _create_path(os.getenv("HOME") or "~/")
    if decompiler == GHIDRA_DECOMPILER:
        # Ghidra plugins isn't in install root, so just attempt to use default
        default_path = home / "ghidra_scripts"
        return default_path if default_path.exists() else None

    if decompiler == IDA_DECOMPILER:
        default_path = home / ".idapro" / "plugins"
        return default_path if default_path.exists() else None

    if decompiler == BINJA_DECOMPILER:
        default_path = home / ".binaryninja" / "plugins"
        return default_path if default_path.exists() else None

    return None
