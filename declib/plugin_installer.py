import os
import platform
from pathlib import Path
import textwrap
import sys
import shutil
from typing import Optional, Union, Tuple

from prompt_toolkit import prompt
from prompt_toolkit.completion.filesystem import PathCompleter


class Color:
    """
    Used to colorify terminal output.
    Taken from: https://github.com/hugsy/gef/blob/dev/tests/utils.py
    """
    NORMAL = "\x1b[0m"
    GRAY = "\x1b[1;38;5;240m"
    LIGHT_GRAY = "\x1b[0;37m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"
    PINK = "\x1b[35m"
    CYAN = "\x1b[36m"
    BOLD = "\x1b[1m"
    UNDERLINE = "\x1b[4m"
    UNDERLINE_OFF = "\x1b[24m"
    HIGHLIGHT = "\x1b[3m"
    HIGHLIGHT_OFF = "\x1b[23m"
    BLINK = "\x1b[5m"
    BLINK_OFF = "\x1b[25m"


class PluginInstaller:
    DECOMPILERS = (
        "ida",
        "binja",
        "ghidra",
        "angr"
    )

    DEBUGGERS = (
        "gdb",
    )

    def __init__(self, targets=None, target_install_paths=None):
        self.targets = targets if targets is not None else self.DECOMPILERS+self.DEBUGGERS
        self._home = Path(os.getenv("HOME") or "~/").expanduser().absolute()
        self.target_install_paths = target_install_paths or {} #or self._populate_installs_from_config()
        self._successful_installs = {}

    @staticmethod
    def find_pkg_files(pkg_name):
        if sys.version_info >= (3, 9):
            import importlib.resources
            path = str(importlib.resources.files(pkg_name))
        else:
            import pkg_resources
            path = pkg_resources.resource_filename(pkg_name, "")

        return Path(path).absolute()

    def install(self, interactive=True, paths_by_target=None):
        self.target_install_paths.update(paths_by_target or {})
        self.display_prologue()

        if interactive:
            self.display_install_instructions()

        try:
            self.install_targets(interactive=interactive)
        except Exception as e:
            print(f"Stopping Install... because: {e}")
        except KeyboardInterrupt:
            print("Goodbye...")

        self.display_epilogue()

    def display_prologue(self):
        pass

    def display_install_instructions(self):
        print(textwrap.dedent("""
        Each decompiler/debugger will be prompted for install below. If you would like to skip install for something
        you can enter 'n' or just hit enter. Each path prompt has tab path completion.
        Enter nothing in each path prompt to get the default listed.
        """))

    def display_epilogue(self):
        self.good("Plugin install completed! If anything was skipped by mistake, please manually install it.")

    @staticmethod
    def info(msg):
        print(f"{Color.BLUE}{msg}{Color.NORMAL}")

    @staticmethod
    def good(msg):
        print(f"{Color.GREEN}[+] {msg}{Color.NORMAL}")

    @staticmethod
    def warn(msg):
        print(f"{Color.YELLOW}[!] {msg}{Color.NORMAL}")

    @staticmethod
    def ask_path(target, location, default=None) -> Optional[Union[bool, Path]]:
        """
        Possible return values:
        - None: install failed or skipped
        - Path: install succeeded
        """

        PluginInstaller.info(f"Install for {target}? [y/n]")
        res = prompt("")
        if res.lower() != "y":
            return None

        PluginInstaller.info(location + f" [default = {default}] (enter nothing to use default): ")
        filepath = prompt("", completer=PathCompleter(expanduser=True))
        if not filepath and default:
            return default

        filepath = Path(filepath).expanduser().absolute()
        if not filepath.exists():
            PluginInstaller.warn(f"Provided filepath {filepath} does not exist. {'Using default.' if default else 'Skipping.'}")
            return default if default else None

        return filepath

    @staticmethod
    def link_or_copy(src, dst, is_dir=False, symlink=False):
        if platform.platform().startswith("Windows"):
            # you can't symlink on windows, so just copy
            symlink = False

        # clean the install location
        shutil.rmtree(dst, ignore_errors=True)
        try:
            os.unlink(dst)
        except:
            pass

        if not symlink:
            # copy if symlinking is not available on target system
            if is_dir:
                shutil.copytree(src, dst)
            else:
                shutil.copy(src, dst)
        else:
            # first attempt a symlink, if it works, exit early
            try:
                os.symlink(src, dst, target_is_directory=is_dir)
                return
            except:
                pass

    @staticmethod
    def _get_path_without_ask(path, default_path=None, interactive=True) -> Tuple[Path, bool]:
        path = Path(path) if path else None
        if not interactive and path.exists():
            return path, True

        if path and path.exists():
            default_path = path
        else:
            default_path = Path(default_path) if default_path else None
            if not default_path or not default_path.exists():
                default_path = None

        return default_path, (not interactive and default_path and default_path.exists())

    def install_targets(self, interactive=True):
        for target in self.targets:
            try:
                target_installer = getattr(self, f"install_{target}")
            except AttributeError:
                continue

            path = self.target_install_paths.get(f"{target}", None)
            if path:
                path = Path(path).expanduser().absolute()

            if not path and not interactive:
                continue

            res = target_installer(path=path, interactive=interactive)
            if res is None:
                self.warn(f"Skipping or failed install for {target}... {Color.NORMAL}\n")
            else:
                self.good(f"Installed {target} to {res}\n")
                self._successful_installs[target] = res
                #GlobalConfig.update_or_make(self._home, **{f"{target}_path": res.parent})

    def install_ida(self, path=None, interactive=True):
        default_path, skip_ask = self._get_path_without_ask(
            path, default_path=self._home.joinpath(".idapro").joinpath("plugins").expanduser(), interactive=interactive
        )
        return self.ask_path("IDA Pro", "Plugins Path", default=default_path) if not skip_ask \
            else default_path

    def install_ghidra(self, path=None, interactive=True):
        potential_path = self._home.joinpath('ghidra_scripts').expanduser()
        if self._home.exists() and not potential_path.exists():
            self.info(f"Creating Ghidra Scripts directory at {potential_path}...")
            potential_path.mkdir()

        default_path, skip_ask = self._get_path_without_ask(
            path, default_path=potential_path, interactive=interactive
        )
        return self.ask_path("Ghidra", "Ghidra Scripts Path", default=default_path) if not skip_ask \
            else default_path

    def install_binja(self, path=None, interactive=True):
        os_name = platform.system()
        if os_name == "Windows":
            default_path = Path(os.environ.get("APPDATA", str(self._home))) / "Binary Ninja" / "plugins"
        elif os_name == "Darwin":
            default_path = (self._home / "Library" / "Application Support" / "Binary Ninja" / "plugins").expanduser()
        else:
            default_path = (self._home / ".binaryninja" / "plugins").expanduser()
        default_path, skip_ask = self._get_path_without_ask(
            path, default_path=default_path,
            interactive=interactive
        )
        return self.ask_path("Binary Ninja", "Plugins Path", default=default_path) if not skip_ask \
            else default_path

    def install_angr(self, path=None, interactive=True):
        # attempt to find the plugins folder for angr-management which is installed via pip
        angr_resolved = True
        try:
            import angrmanagement
        except ImportError:
            angr_resolved = False
        default_path = Path(angrmanagement.__file__).parent / "plugins" if angr_resolved else None

        default_path, skip_ask = self._get_path_without_ask(path, default_path=default_path, interactive=interactive)
        return self.ask_path("angr-management", "angr-management Plugins Path", default=default_path) if not skip_ask \
            else default_path

    def install_gdb(self, path=None, interactive=True):
        default_path, skip_ask = self._get_path_without_ask(
            path, default_path=self._home.joinpath(".gdbinit").expanduser(),
            interactive=interactive
        )
        return self.ask_path("GDB", "gdbinit Path", default=default_path) if not skip_ask \
            else default_path


class DecLibPluginInstaller(PluginInstaller):
    def __init__(self, targets=None, target_install_paths=None):
        targets = targets or PluginInstaller.DECOMPILERS
        super().__init__(targets=targets, target_install_paths=target_install_paths)
        self._declib_plugins_path = self.find_pkg_files("declib").joinpath("decompiler_stubs")

    def display_prologue(self):
        print(textwrap.dedent("""
        Now installing DecLib plugins for all supported decompilers..."""))
