import argparse

from . import DLChangeWatcherInstaller, create_plugin
import dl_change_watcher


def main():
    parser = argparse.ArgumentParser(description="An example CLI for the example change watcher plugin")
    parser.add_argument(
        "-i", "--install", action="store_true", help="Install plugin into your decompilers"
    )
    parser.add_argument(
        "-s", "--server", help="Run a a headless server for the watcher plugin", choices=["ghidra"]
    )
    parser.add_argument("-v", "--version", action="version", version=dl_change_watcher.__version__)
    args = parser.parse_args()

    if args.install:
        DLChangeWatcherInstaller().install()
    elif args.server:
        if args.server != "ghidra":
            raise NotImplementedError("Only Ghidra is supported for now")

        create_plugin(force_decompiler="ghidra")


if __name__ == "__main__":
    main()
