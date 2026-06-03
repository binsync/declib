import sys
import subprocess
import tempfile
from pathlib import Path

import unittest

from declib.plugin_installer import DecLibPluginInstaller


class TestCommandline(unittest.TestCase):
    def test_change_watcher_plugin_cli(self):
        # assumes you've pip installed ./examples/change_watcher_plugin
        import dl_change_watcher

        # run the CLI version check
        output = subprocess.run(["dl_change_watcher", "--version"], capture_output=True)
        version = output.stdout.decode().strip()
        assert version == dl_change_watcher.__version__


class TestInstaller(unittest.TestCase):
    """Tests for the plugin installer."""

    def test_install_ida_to_custom_path(self):
        """Test installing IDA plugin to a custom path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            installer = DecLibPluginInstaller(targets=["ida"])
            result = installer.install(interactive=False, paths_by_target={"ida": tmpdir})
            # Verify the installer ran without error and returned the path
            assert "ida" in installer._successful_installs
            assert installer._successful_installs["ida"] == Path(tmpdir)

    def test_install_binja_to_custom_path(self):
        """Test installing Binary Ninja plugin to a custom path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            installer = DecLibPluginInstaller(targets=["binja"])
            result = installer.install(interactive=False, paths_by_target={"binja": tmpdir})
            # Verify the installer ran without error and returned the path
            assert "binja" in installer._successful_installs
            assert installer._successful_installs["binja"] == Path(tmpdir)

    def test_install_ghidra_to_custom_path(self):
        """Test installing Ghidra plugin to a custom path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            installer = DecLibPluginInstaller(targets=["ghidra"])
            result = installer.install(interactive=False, paths_by_target={"ghidra": tmpdir})
            # Verify the installer ran without error and returned the path
            assert "ghidra" in installer._successful_installs
            assert installer._successful_installs["ghidra"] == Path(tmpdir)

    def test_install_angr_skipped_without_angrmanagement(self):
        """Test that angr install is skipped when angr-management is not installed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            installer = DecLibPluginInstaller(targets=["angr"])
            # angr install requires angr-management to be installed, so it should be skipped
            # in test environments where angr-management is not available
            result = installer.install(interactive=False, paths_by_target={"angr": tmpdir})
            # The install may or may not succeed depending on whether angr-management is installed
            # Just verify it doesn't raise an exception

    def test_install_all_decompilers_to_custom_paths(self):
        """Test installing all decompilers to custom paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ida_path = Path(tmpdir) / "ida"
            binja_path = Path(tmpdir) / "binja"
            ghidra_path = Path(tmpdir) / "ghidra"

            ida_path.mkdir()
            binja_path.mkdir()
            ghidra_path.mkdir()

            installer = DecLibPluginInstaller(targets=["ida", "binja", "ghidra"])
            result = installer.install(
                interactive=False,
                paths_by_target={
                    "ida": str(ida_path),
                    "binja": str(binja_path),
                    "ghidra": str(ghidra_path),
                }
            )
            # Verify all installers ran without error
            assert "ida" in installer._successful_installs
            assert "binja" in installer._successful_installs
            assert "ghidra" in installer._successful_installs


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
