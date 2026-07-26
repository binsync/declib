"""Server-side error text must survive the trip back to the client.

Regression test for a blank error observed in the wild:

    Request failed:  for {'type': 'method_call',
                          'method_name': 'get_func_containing', ...}

Note the empty text after "failed:" -- the real cause was dropped.
"""
import logging
import unittest
from unittest.mock import patch

from declib.api.decompiler_client import DecompilerClient


class _FakeSocket:
    pass


def _client_with_response(response):
    """Build a client that does no I/O and yields one canned response."""
    client = DecompilerClient.__new__(DecompilerClient)
    client._socket = _FakeSocket()
    client._socket_lock = __import__("threading").Lock()
    with patch("declib.api.decompiler_client.SocketProtocol") as proto:
        proto.send_message.return_value = None
        proto.recv_message.return_value = response
        return client


class TestErrorPropagation(unittest.TestCase):
    def _send(self, response):
        client = _client_with_response(response)
        with patch("declib.api.decompiler_client.SocketProtocol") as proto:
            proto.send_message.return_value = None
            proto.recv_message.return_value = response
            return client._send_request({"type": "method_call",
                                         "method_name": "get_func_containing"})

    def test_empty_error_falls_back_to_traceback(self):
        """An exception with no message must not surface as blank."""
        with self.assertRaises(RuntimeError) as ctx:
            self._send({
                "error": "",
                "type": "ConnectionResetError",
                "traceback": "Traceback (most recent call last):\n  RealCause: boom",
            })
        text = str(ctx.exception)
        assert "ConnectionResetError" in text
        assert "RealCause: boom" in text

    def test_empty_error_without_traceback_still_names_the_type(self):
        with self.assertRaises(RuntimeError) as ctx:
            self._send({"error": "", "type": "IndexError"})
        assert "IndexError" in str(ctx.exception)

    def test_normal_error_text_is_unchanged(self):
        with self.assertRaises(ValueError) as ctx:
            self._send({"error": "bad address 0x41", "type": "ValueError"})
        assert str(ctx.exception) == "bad address 0x41"

    def test_log_line_names_the_exception_type(self):
        """The log must never read 'Request failed:  for ...'."""
        with self.assertLogs("declib.api.decompiler_client", level=logging.ERROR) as logs:
            with self.assertRaises(RuntimeError):
                self._send({"error": "", "type": "ConnectionResetError"})
        joined = "\n".join(logs.output)
        assert "Request failed:  for" not in joined
        assert "ConnectionResetError" in joined


if __name__ == "__main__":
    unittest.main()
