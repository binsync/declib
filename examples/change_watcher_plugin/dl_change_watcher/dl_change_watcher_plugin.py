# An example DecLib plugin that will print when every artifact is changed inside the decompiler
# @author BinSync
# @category BinSync
# @menupath Tools.ArtifactChangeWatcher.Start the BS backed for watcher

# Note: this requires that your plugin, which is a package, exposes a function called `create_plugin` AND it
# exposes a command line interface that can be run (for Ghidra).
plugin_command = "dl_change_watcher -s ghidra"
def create_plugin(*args, **kwargs):
    from dl_change_watcher import create_plugin as _create_plugin
    return _create_plugin(*args, **kwargs)


# =============================================================================
# DecLib generic plugin loader (don't touch)
# =============================================================================

import sys
# Python 2 has special requirements for Ghidra, which forces us to use a different entry point
# and scope for defining plugin entry points
if sys.version[0] == "2":
    # Do Ghidra Py2 entry point
    import subprocess
    from declib_vendored.ghidra_bridge_server import GhidraBridgeServer

    GhidraBridgeServer.run_server(background=True)
    process = subprocess.Popen(plugin_command.split(" "))
    if process.poll() is not None:
        raise RuntimeError("Failed to run the Python3 backed. It's likely Python3 is not in your Path inside Ghidra.")
else:
    # Try plugin discovery for other decompilers
    try:
        import idaapi
        has_ida = True
    except ImportError:
        has_ida = False
    try:
        import angrmanagement
        has_angr = True
    except ImportError:
        has_angr = False

    if not has_ida and not has_angr:
        create_plugin()
    elif has_angr:
        from angrmanagement.plugins import BasePlugin
        class AngrDLPluginThunk(BasePlugin):
            def __init__(self, workspace):
                super().__init__(workspace)
                globals()["workspace"] = workspace
                self.plugin = create_plugin()

            def teardown(self):
                pass


def PLUGIN_ENTRY(*args, **kwargs):
    """
    This is the entry point for IDA to load the plugin.
    """
    return create_plugin(*args, **kwargs)
