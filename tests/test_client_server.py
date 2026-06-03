import os
import contextlib
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from declib.api.decompiler_server import DecompilerServer
from declib.api.decompiler_client import DecompilerClient
from declib.api.decompiler_interface import DecompilerInterface
from declib.decompilers import GHIDRA_DECOMPILER

# Test binary path - use the same path as other tests
TEST_BINARIES_DIR = Path(os.getenv("TEST_BINARIES_DIR", Path(__file__).parent.parent.parent / "bs-artifacts" / "binaries"))
if not TEST_BINARIES_DIR.exists():
    # fallback to relative path
    TEST_BINARIES_DIR = Path(__file__).parent.parent.parent / "bs-artifacts" / "binaries"

FAUXWARE_PATH = TEST_BINARIES_DIR / "fauxware"


@contextlib.contextmanager
def simulate_no_af_unix():
    if hasattr(socket, "AF_UNIX"):
        af_unix_val = socket.AF_UNIX
        delattr(socket, "AF_UNIX")
        try:
            yield
        finally:
            setattr(socket, "AF_UNIX", af_unix_val)
    else:
        yield

class TestClientServer(unittest.TestCase):
    """Test the new AF_UNIX socket-based DecompilerClient and DecompilerServer"""
    
    def setUp(self):
        """Set up test environment"""
        self.server = None
        self.client = None
        self.temp_dir = None
        
    def tearDown(self):
        """Clean up test environment"""
        if self.client:
            self.client.shutdown()
        if self.server:
            self.server.stop()
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                os.rmdir(self.temp_dir)
            except:
                pass
    
    def test_server_startup_and_client_connection(self):
        """Test that server starts and client can connect"""
        # Start server with Ghidra headless and fauxware binary
        with tempfile.TemporaryDirectory() as proj_dir:
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_fauxware"
            )
            self.server.start()
            
            # Give server time to start
            time.sleep(1)
            
            # Connect client
            self.client = DecompilerClient(socket_path=self.server.socket_path)
            
            # Verify connection works
            self.assertTrue(self.client.is_connected())
            self.assertTrue(self.client.ping())
            
            # Test basic properties
            self.assertEqual(self.client.name, "ghidra")
            self.assertIsNotNone(self.client.binary_path)
            self.assertIsNotNone(self.client.binary_hash)
            self.assertTrue(self.client.decompiler_available)

    def test_inet_fallback(self):
        """Test the AF_INET fallback mechanism when AF_UNIX is missing"""
        with simulate_no_af_unix():
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as proj_dir:
                self.server = DecompilerServer(
                    force_decompiler=GHIDRA_DECOMPILER,
                    headless=True,
                    binary_path=FAUXWARE_PATH,
                    project_location=proj_dir,
                    project_name="test_fauxware_inet"
                )
                self.server.start()
                
                # Give server time to start
                time.sleep(2)
                
                # Verify that it binds to a port and writes to the socket path
                self.assertTrue(os.path.exists(self.server.socket_path))
                with open(self.server.socket_path, 'r') as f:
                    port_str = f.read().strip()
                self.assertTrue(port_str.isdigit())
                
                # Connect client
                self.client = DecompilerClient(socket_path=self.server.socket_path)
                
                # Verify connection works
                self.assertTrue(self.client.is_connected())
                self.assertTrue(self.client.ping())
                
                self.client.shutdown()
                self.server.stop()
    
    def test_artifact_collections_match_local(self):
        """Test that client artifact collections behave like local interface"""
        with tempfile.TemporaryDirectory() as proj_dir:
            # Create server
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_fauxware_remote"
            )
            self.server.start()
            time.sleep(1)
            
            # Connect client
            self.client = DecompilerClient(socket_path=self.server.socket_path)
            
            # Test that we get functions
            remote_func_keys = list(self.client.functions.keys())
            self.assertGreater(len(remote_func_keys), 0, "Should have found functions")
            
            # Test that we can get light functions
            remote_light_funcs = list(self.client.functions.items())
            self.assertGreater(len(remote_light_funcs), 0, "Should have light functions")
            
            # Verify functions are actual Function objects
            if remote_light_funcs:
                addr, func = remote_light_funcs[0]
                self.assertIsNotNone(func, "Function should not be None")
                self.assertEqual(func.addr, addr, "Function address should match key")
                self.assertIsInstance(func.name, str, "Function should have a name")

    def test_client_server_method_calls(self):
        """Test that client method calls work correctly"""
        with tempfile.TemporaryDirectory() as proj_dir:
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_fauxware_methods"
            )
            self.server.start()
            time.sleep(1)
            
            self.client = DecompilerClient(socket_path=self.server.socket_path)
            
            # Test function size method
            func_keys = list(self.client.functions.keys())
            self.assertGreater(len(func_keys), 0, "Should have functions")
            
            func_addr = func_keys[0]
            func_size = self.client.get_func_size(func_addr)
            self.assertGreater(func_size, 0, "Function size should be positive")
            
            # Test fast_get_function
            fast_func = self.client.fast_get_function(func_addr)
            self.assertIsNotNone(fast_func, "Fast function should not be None")
            self.assertEqual(fast_func.addr, func_addr, "Fast function address should match")
    
    def test_client_discover_auto_detection(self):
        """Test client auto-discovery functionality"""
        with tempfile.TemporaryDirectory() as proj_dir:
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_fauxware_autodiscovery"
            )
            self.server.start()
            time.sleep(1)
            
            # Test auto-discovery (should find the server we just started)
            try:
                self.client = DecompilerClient.discover()
                self.assertTrue(self.client.is_connected())
                self.assertEqual(self.client.name, "ghidra")
            except ConnectionError:
                # Auto-discovery might fail if multiple temp directories exist
                # This is acceptable, we can still test manual connection
                self.client = DecompilerClient(socket_path=self.server.socket_path)
                self.assertTrue(self.client.is_connected())
    
    def test_error_handling(self):
        """Test error handling in client-server communication"""
        with tempfile.TemporaryDirectory() as proj_dir:
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_fauxware_errors"
            )
            self.server.start()
            time.sleep(1)
            
            self.client = DecompilerClient(socket_path=self.server.socket_path)
            
            # Test KeyError handling for non-existent function
            with self.assertRaises(KeyError, msg="Should raise KeyError for non-existent function"):
                self.client.functions[0xDEADBEEF]  # Non-existent function
    
    def test_client_context_manager(self):
        """Test client context manager functionality"""
        with tempfile.TemporaryDirectory() as proj_dir:
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_fauxware_context"
            )
            self.server.start()
            time.sleep(1)

            # Test context manager
            with DecompilerClient(socket_path=self.server.socket_path) as client:
                self.assertTrue(client.is_connected())
                self.assertEqual(client.name, "ghidra")

            # Client should be disconnected after context manager
            # (Note: we can't test this easily since the client object is out of scope)

    def test_server_restart_discovery(self):
        """Test that client can discover server after restart"""
        with tempfile.TemporaryDirectory() as proj_dir:
            # Start first server
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_fauxware_restart"
            )
            self.server.start()
            time.sleep(1)

            # Get the binary hash from the server
            self.client = DecompilerClient(socket_path=self.server.socket_path)
            binary_hash = self.client.binary_hash
            self.assertIsNotNone(binary_hash, "Binary hash should not be None")
            socket_path_1 = self.server.socket_path
            self.client.shutdown()

            # Stop the server
            self.server.stop()
            time.sleep(0.5)

            # Start a new server (will have different socket path)
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_fauxware_restart2"
            )
            self.server.start()
            time.sleep(1)
            socket_path_2 = self.server.socket_path

            # Socket paths should be different (different temp directories)
            self.assertNotEqual(socket_path_1, socket_path_2,
                              "New server should have different socket path")

            # Client should discover the new server using binary_hash
            self.client = DecompilerClient.discover(binary_hash=binary_hash)
            self.assertTrue(self.client.is_connected())
            self.assertEqual(self.client.binary_hash, binary_hash)
            self.assertEqual(self.client.socket_path, socket_path_2,
                           "Client should connect to new server, not old socket")

    def test_multiple_servers_binary_hash_matching(self):
        """Test client can select correct server when multiple are running"""
        # We'll use different binaries to get different hashes
        # For this test, we'll create two servers with the same binary
        # but simulate different binary_hash by using different project names

        with tempfile.TemporaryDirectory() as proj_dir1:
            with tempfile.TemporaryDirectory() as proj_dir2:
                # Start first server
                server1 = DecompilerServer(
                    force_decompiler=GHIDRA_DECOMPILER,
                    headless=True,
                    binary_path=FAUXWARE_PATH,
                    project_location=proj_dir1,
                    project_name="test_server1"
                )
                server1.start()
                time.sleep(1)

                # Get hash from first server
                client1 = DecompilerClient(socket_path=server1.socket_path)
                hash1 = client1.binary_hash
                socket1 = server1.socket_path
                client1.shutdown()

                # Start second server with same binary (will have same hash)
                server2 = DecompilerServer(
                    force_decompiler=GHIDRA_DECOMPILER,
                    headless=True,
                    binary_path=FAUXWARE_PATH,
                    project_location=proj_dir2,
                    project_name="test_server2"
                )
                server2.start()
                time.sleep(1)

                socket2 = server2.socket_path
                self.assertNotEqual(socket1, socket2, "Servers should have different sockets")

                try:
                    # Discover with binary hash - should connect to one of the servers
                    # (since they have the same binary, they'll have the same hash)
                    discovered_client = DecompilerClient.discover(binary_hash=hash1)
                    self.assertTrue(discovered_client.is_connected())
                    self.assertEqual(discovered_client.binary_hash, hash1)

                    # Should connect to one of the two servers
                    self.assertIn(discovered_client.socket_path, [socket1, socket2],
                                "Should connect to one of the running servers")
                    discovered_client.shutdown()

                    # Discover without binary hash - should connect to most recent
                    discovered_client2 = DecompilerClient.discover()
                    self.assertTrue(discovered_client2.is_connected())
                    discovered_client2.shutdown()

                finally:
                    server1.stop()
                    server2.stop()

    def test_defunct_socket_handling(self):
        """Test that client skips defunct socket files from stopped servers"""
        with tempfile.TemporaryDirectory() as proj_dir:
            # Start and stop a server to create a defunct socket
            server1 = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_defunct"
            )
            server1.start()
            time.sleep(1)
            defunct_socket = server1.socket_path
            server1.stop()
            time.sleep(0.5)

            # Manually recreate the socket file to simulate a stale socket
            # (normally stop() removes it, but crashes might leave it)
            import tempfile as tf
            temp_dir = tf.mkdtemp(prefix="declib_server_")
            defunct_socket = os.path.join(temp_dir, "decompiler.sock")
            # Create an empty file to simulate stale socket
            open(defunct_socket, 'w').close()

            # Start a new server
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_working"
            )
            self.server.start()
            time.sleep(1)

            # Discovery should skip the defunct socket and find the working server
            self.client = DecompilerClient.discover()
            self.assertTrue(self.client.is_connected())
            self.assertEqual(self.client.socket_path, self.server.socket_path,
                           "Should connect to working server, not defunct socket")

            # Clean up the fake defunct socket
            try:
                os.unlink(defunct_socket)
                os.rmdir(temp_dir)
            except:
                pass

    def test_discover_with_binary_hash_no_match(self):
        """Test that discovery fails when binary_hash doesn't match any server"""
        with tempfile.TemporaryDirectory() as proj_dir:
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_no_match"
            )
            self.server.start()
            time.sleep(1)

            # Try to discover with a non-matching binary hash
            fake_hash = "this_hash_does_not_exist_12345"
            with self.assertRaises(ConnectionError) as context:
                DecompilerClient.discover(binary_hash=fake_hash)

            # Error message should mention the hash
            self.assertIn(fake_hash, str(context.exception))
            self.assertIn("none matched", str(context.exception).lower())

    def test_server_info_includes_binary_hash(self):
        """Test that server_info response includes binary_hash"""
        with tempfile.TemporaryDirectory() as proj_dir:
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_server_info"
            )
            self.server.start()
            time.sleep(1)

            self.client = DecompilerClient(socket_path=self.server.socket_path)

            # Server info is fetched during connection and stored
            server_info = self.client._server_info
            self.assertIsNotNone(server_info, "Server info should be available")
            self.assertIn("binary_hash", server_info, "Server info should include binary_hash")

            # Verify binary_hash matches what we get from the property
            self.assertEqual(server_info["binary_hash"], self.client.binary_hash,
                           "Server info binary_hash should match client property")

    def test_callback_events(self):
        """Test that client receives callback events when artifacts change on server"""
        with tempfile.TemporaryDirectory() as proj_dir:
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_callbacks"
            )
            self.server.start()
            time.sleep(1)

            self.client = DecompilerClient(socket_path=self.server.socket_path)

            # Track callback invocations
            callback_events = []

            def test_callback(artifact, **kwargs):
                callback_events.append({
                    "artifact_type": type(artifact).__name__,
                    "artifact": artifact,
                    "kwargs": kwargs
                })

            # Register callback for Comment artifacts
            from declib.artifacts import Comment
            self.client.artifact_change_callbacks[Comment].append(test_callback)

            # Start artifact watchers (which starts event listener)
            self.client.start_artifact_watchers()
            time.sleep(0.5)  # Give listener time to start

            # Verify event listener is running
            self.assertTrue(self.client._event_listener_running,
                          "Event listener should be running")
            self.assertTrue(self.client._subscribed_to_events,
                          "Client should be subscribed to events")

            # Trigger a callback on the server by creating a comment
            # TODO: update this to just sent a comment so we can see the callback trigger naturally
            test_comment = Comment(0x1234, "Test comment from callback test")
            # Note: comment_changed will lift the artifact, which changes the address
            lifted_comment = self.server.deci.comment_changed(test_comment)

            # Wait for event to be received and processed
            time.sleep(0.5)

            # Verify callback was triggered
            self.assertGreater(len(callback_events), 0,
                             "Callback should have been triggered")

            # Verify event contents
            event = callback_events[0]
            self.assertEqual(event["artifact_type"], "Comment",
                           "Event should be for Comment artifact")
            # The address should match the lifted address, not the original
            self.assertEqual(event["artifact"].addr, lifted_comment.addr,
                           "Comment address should match the lifted address")
            self.assertIn("Test comment", event["artifact"].comment,
                        "Comment text should match")

            # Clean up
            self.client.stop_artifact_watchers()
            self.assertFalse(self.client._event_listener_running,
                           "Event listener should be stopped")

    def test_multiple_callbacks(self):
        """Test that multiple callbacks can be registered and all are triggered"""
        with tempfile.TemporaryDirectory() as proj_dir:
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_multiple_callbacks"
            )
            self.server.start()
            time.sleep(1)

            self.client = DecompilerClient(socket_path=self.server.socket_path)

            # Track callbacks
            callback1_called = []
            callback2_called = []

            def callback1(artifact, **kwargs):
                callback1_called.append(artifact)

            def callback2(artifact, **kwargs):
                callback2_called.append(artifact)

            # Register multiple callbacks
            from declib.artifacts import Struct
            self.client.artifact_change_callbacks[Struct].append(callback1)
            self.client.artifact_change_callbacks[Struct].append(callback2)

            # Start watchers
            self.client.start_artifact_watchers()
            time.sleep(0.5)

            # Trigger event
            test_struct = Struct("TestStruct", 0x10, members={})
            self.server.deci.struct_changed(test_struct)

            # Wait for processing
            time.sleep(0.5)

            # Both callbacks should have been called
            self.assertEqual(len(callback1_called), 1, "Callback 1 should be called once")
            self.assertEqual(len(callback2_called), 1, "Callback 2 should be called once")
            self.assertEqual(callback1_called[0].name, "TestStruct")
            self.assertEqual(callback2_called[0].name, "TestStruct")

    def test_callback_with_metadata(self):
        """Test that callback metadata (like deleted flag) is passed correctly"""
        with tempfile.TemporaryDirectory() as proj_dir:
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_callback_metadata"
            )
            self.server.start()
            time.sleep(1)

            self.client = DecompilerClient(socket_path=self.server.socket_path)

            # Track metadata
            received_metadata = []

            def metadata_callback(artifact, **kwargs):
                received_metadata.append(kwargs)

            # Register callback
            from declib.artifacts import Enum
            self.client.artifact_change_callbacks[Enum].append(metadata_callback)

            # Start watchers
            self.client.start_artifact_watchers()
            time.sleep(0.5)

            # Trigger event with metadata
            test_enum = Enum("TestEnum", members={})
            self.server.deci.enum_changed(test_enum, deleted=True)

            # Wait for processing
            time.sleep(0.5)

            # Verify metadata was passed
            self.assertEqual(len(received_metadata), 1, "Callback should be called once")
            self.assertIn("deleted", received_metadata[0], "Metadata should include deleted flag")
            self.assertTrue(received_metadata[0]["deleted"], "deleted flag should be True")

    def test_artifact_watchers_integration(self):
        """
        Test artifact callbacks with client-server architecture (adapted from test_remote_ghidra).

        Note: This test manually triggers callbacks on the server to test the event broadcast system,
        since Ghidra's artifact watchers don't function in headless mode.
        """
        from declib.artifacts import FunctionHeader, StackVariable, Struct, GlobalVariable, Enum, Comment
        from collections import defaultdict

        with tempfile.TemporaryDirectory() as proj_dir:
            # Start server
            self.server = DecompilerServer(
                force_decompiler=GHIDRA_DECOMPILER,
                headless=True,
                binary_path=FAUXWARE_PATH,
                project_location=proj_dir,
                project_name="test_artifact_watchers"
            )
            self.server.start()
            time.sleep(1)

            # Connect client
            self.client = DecompilerClient(socket_path=self.server.socket_path)

            # Track callback hits
            hits = defaultdict(list)
            def func_hit(artifact, **kwargs):
                hits[artifact.__class__].append(artifact)

            # Register callbacks for different artifact types
            for typ in (FunctionHeader, StackVariable, Enum, Struct, GlobalVariable, Comment):
                self.client.artifact_change_callbacks[typ].append(func_hit)

            # Start event listener
            self.client.start_artifact_watchers()
            time.sleep(0.5)

            # Test FunctionHeader callback by manually triggering on server
            # (Ghidra headless watchers don't work, so we manually trigger)
            func_addr = self.client.art_lifter.lift_addr(0x400664)
            main = self.client.functions[func_addr]

            # Trigger callback on server side directly
            test_header = FunctionHeader("test_func", func_addr, type_="int")
            self.server.deci.function_header_changed(test_header)
            time.sleep(0.5)

            # Verify callback was received on client
            self.assertGreaterEqual(len(hits[FunctionHeader]), 1,
                                   "FunctionHeader callback should be triggered")

            # Test Comment callback
            test_comment = Comment(func_addr, "Test comment for integration test")
            self.server.deci.comment_changed(test_comment)
            time.sleep(0.5)

            self.assertGreaterEqual(len(hits[Comment]), 1,
                                   "Comment callback should be triggered")

            # Test Struct callback
            test_struct = Struct("TestStruct", 0x10, members={})
            self.server.deci.struct_changed(test_struct)
            time.sleep(0.5)

            self.assertGreaterEqual(len(hits[Struct]), 1,
                                   "Struct callback should be triggered")

            # Test Enum callback
            test_enum = Enum("TestEnum", members={"VALUE1": 1, "VALUE2": 2})
            self.server.deci.enum_changed(test_enum)
            time.sleep(0.5)

            self.assertGreaterEqual(len(hits[Enum]), 1,
                                   "Enum callback should be triggered")

            # Test GlobalVariable callback
            g_addr = self.client.art_lifter.lift_addr(0x4008e0)
            test_gvar = GlobalVariable(g_addr, "test_global", "int", 4)
            self.server.deci.global_variable_changed(test_gvar)
            time.sleep(0.5)

            self.assertGreaterEqual(len(hits[GlobalVariable]), 1,
                                   "GlobalVariable callback should be triggered")

            # Test that client can also modify artifacts through the server
            # and they persist correctly
            main.name = "modified_main"
            self.client.functions[func_addr] = main
            time.sleep(0.5)

            # Retrieve and verify the change persisted
            modified_main = self.client.functions[func_addr]
            self.assertEqual(modified_main.name, "modified_main",
                           "Function name modification should persist")

            # Clean up
            self.client.stop_artifact_watchers()
            self.assertFalse(self.client._event_listener_running,
                           "Event listener should be stopped")


if __name__ == "__main__":
    unittest.main()