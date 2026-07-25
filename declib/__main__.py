import argparse
import sys
import logging

from declib.plugin_installer import DecLibPluginInstaller

_l = logging.getLogger(__name__)


def install():
    DecLibPluginInstaller().install()


def start_server(
    socket_path=None, decompiler=None, binary_path=None, headless=False,
    server_id=None, project_dir=None,
):
    """Start the DecompilerServer (AF_UNIX socket-based)"""
    try:
        from declib.api.decompiler_server import DecompilerServer
        from declib.api.decompiler_interface import DecompilerInterface

        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        # Prepare interface kwargs
        interface_kwargs = {}
        if decompiler:
            interface_kwargs['force_decompiler'] = decompiler
        if binary_path:
            interface_kwargs['binary_path'] = binary_path
        if headless:
            interface_kwargs['headless'] = headless
        if project_dir:
            interface_kwargs['project_dir'] = project_dir

        # Create and start server
        if socket_path:
            _l.info(f"Starting AF_UNIX DecompilerServer on {socket_path}")
        else:
            _l.info("Starting AF_UNIX DecompilerServer with auto-generated socket path")
        if interface_kwargs:
            _l.info(f"Interface options: {interface_kwargs}")

        with DecompilerServer(socket_path=socket_path, server_id=server_id, **interface_kwargs) as server:
            _l.info("Server started successfully. Press Ctrl+C to stop.")
            _l.info("Connect with: DecompilerClient.discover('unix://{}')".format(server.socket_path))
            try:
                server.wait_for_shutdown()
            except KeyboardInterrupt:
                _l.info("Shutting down server...")

    except ImportError as e:
        _l.error(f"Failed to import required modules: {e}")
        sys.exit(1)
    except Exception as e:
        _l.error(f"Failed to start server: {e}")
        sys.exit(1)


def test_client(server_url=None):
    """Test the DecompilerClient connection"""
    try:
        from declib.api.decompiler_client import DecompilerClient
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        if server_url:
            _l.info(f"Testing connection to DecompilerServer at {server_url}")
        else:
            _l.info("Testing connection to auto-discovered DecompilerServer")
        
        with DecompilerClient.discover(server_url=server_url) as client:
            _l.info(f"Successfully connected to {client.name} decompiler")
            _l.info(f"Binary path: {client.binary_path}")
            _l.info(f"Binary hash: {client.binary_hash}")
            _l.info(f"Decompiler available: {client.decompiler_available}")
            
            # Test fast artifact collections (benchmark performance)
            import time
            start_time = time.time()
            functions = list(client.functions.items())
            end_time = time.time()
            _l.info(f"Retrieved {len(functions)} functions in {end_time - start_time:.3f}s")
            
            start_time = time.time()
            comments = list(client.comments.keys())
            end_time = time.time()
            _l.info(f"Retrieved {len(comments)} comment keys in {end_time - start_time:.3f}s")
            
            _l.info("✅ Client test completed successfully!")
            
    except ImportError as e:
        _l.error(f"Failed to import required modules: {e}")
        sys.exit(1)
    except Exception as e:
        _l.error(f"Client test failed: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
            description="""
            The DecLib Command Line Util. This is the script interface to DecLib that allows you to install and run 
            the Ghidra UI for running plugins, and start the DecompilerServer. 
            """,
            epilog="""
            Examples:
            declib --install | 
            declib --server --socket-path /tmp/my_server.sock | 
            declib --server --decompiler ghidra --binary-path /path/to/binary --headless
            """
    )
    parser.add_argument(
        "--install", action="store_true", help="""
        Install all the DecLib plugins to every decompiler. 
        """
    )
    parser.add_argument(
        "--single-decompiler-install", nargs=2, metavar=('decompiler', 'path'), help="Install DAILA into a single decompiler. Decompiler must be one of: ida, ghidra, binja, angr."
    )
    parser.add_argument(
        "--server", action="store_true", help="""
        Start the DecompilerServer to expose DecompilerInterface APIs over AF_UNIX sockets.
        """
    )
    parser.add_argument(
        "--server-url", help="""
        URL of the DecompilerServer to connect to (e.g., unix:///tmp/server.sock). 
        If not specified, will auto-discover running servers.
        """
    )
    parser.add_argument(
        "--socket-path", help="""
        Path for the AF_UNIX socket (default: auto-generated in temp directory).
        """
    )
    parser.add_argument(
        "--decompiler", choices=["ida", "ghidra", "binja", "angr", "jadx"], help="""
        Force a specific decompiler for the server. If not specified, auto-detection will be used.
        """
    )
    parser.add_argument(
        "--binary-path", help="""
        Path to the binary file to analyze (required for headless mode).
        """
    )
    parser.add_argument(
        "--headless", action="store_true", help="""
        Run the decompiler in headless mode (no GUI). Requires --binary-path.
        """
    )
    parser.add_argument(
        "--server-id", help="""
        Explicit server ID to use; if omitted, a unique one is generated.
        """
    )
    parser.add_argument(
        "--project-dir", help="""
        Directory where the backend should store its project/database files
        (Ghidra project, IDA .id*, etc.). If omitted, backend defaults apply
        (Ghidra creates a project next to the binary; IDA writes .id* next
        to the binary).
        """
    )
    args = parser.parse_args()

    if args.single_decompiler_install:
        decompiler, path = args.single_decompiler_install
        DecLibPluginInstaller().install(interactive=False, paths_by_target={decompiler: path})
    elif args.install:
        install()
    elif args.server:
        if args.headless and not args.binary_path:
            parser.error("--headless requires --binary-path")
        start_server(
            socket_path=args.socket_path,
            decompiler=args.decompiler,
            binary_path=args.binary_path,
            headless=args.headless,
            server_id=args.server_id,
            project_dir=args.project_dir,
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
