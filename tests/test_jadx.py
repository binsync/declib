import os
import shlex
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from declib.api.decompiler_interface import DecompilerInterface
from declib.decompilers.jadx.interface import JadxInterface
from declib.decompilers.jadx.worker_client import JadxWorkerClient


class FakeWorker:
    def __init__(self, **kwargs):
        self.calls = []
        self.closed = False

    def call(self, method, params=None, timeout=None):
        self.calls.append((method, params, timeout))
        if method == "load":
            return {
                "path": params["path"],
                "classes": 2,
                "resources": 1,
                "errors": 0,
                "warnings": 0,
                "capabilities": ["classes", "methods"],
            }
        if method == "list_classes":
            return [{"kind": "class", "ref": "example.Main", "name": "Main"}]
        if method == "method_source":
            return {
                "ref": params["ref"],
                "language": "java",
                "text": "void run() {}",
            }
        return {}

    def close(self):
        self.closed = True


def test_jadx_interface_uses_opaque_managed_references(tmp_path):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"not needed by fake worker")

    with patch(
        "declib.decompilers.jadx.interface.JadxWorkerClient",
        FakeWorker,
    ):
        interface = JadxInterface(binary_path=apk, headless=True)
        try:
            assert interface.binary_base_addr == 0
            assert interface.binary_arch == "dalvik"
            assert interface._functions() == {}
            assert interface.managed_list_classes()[0]["ref"] == "example.Main"
            source = interface.managed_method_source("example.Main->run()V")
            assert source["text"] == "void run() {}"
        finally:
            worker = interface._worker
            interface.shutdown()
            assert worker.closed


def test_discover_constructs_jadx_backend(tmp_path):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"sample")
    sentinel = MagicMock()

    with patch(
        "declib.decompilers.jadx.interface.JadxInterface",
        return_value=sentinel,
    ) as constructor:
        result = DecompilerInterface.discover(
            force_decompiler="jadx",
            binary_path=apk,
            headless=True,
        )

    assert result is sentinel
    constructor.assert_called_once_with(binary_path=apk, headless=True)


def test_worker_client_json_protocol(tmp_path):
    worker = tmp_path / "fake_worker.py"
    worker.write_text(
        """
import json
import sys
for line in sys.stdin:
    request = json.loads(line)
    if request["method"] == "fail":
        response = {
            "id": request["id"],
            "error": {"type": "IllegalArgumentException", "message": "bad input"},
        }
    else:
        response = {
            "id": request["id"],
            "result": {"method": request["method"], "params": request["params"]},
        }
    print(json.dumps(response), flush=True)
""".strip()
        + "\n",
        encoding="utf-8",
    )

    command = f"{shlex.quote(sys.executable)} {shlex.quote(str(worker))}"
    with JadxWorkerClient(executable=command) as client:
        assert client.call("echo", {"value": 7}) == {
            "method": "echo",
            "params": {"value": 7},
        }
        with pytest.raises(ValueError, match="bad input"):
            client.call("fail")


def test_find_official_jadx_runtime_from_home(tmp_path, monkeypatch):
    jadx_home = tmp_path / "jadx"
    jadx_jar = jadx_home / "lib" / "jadx-1.5.6-all.jar"
    jadx_jar.parent.mkdir(parents=True)
    jadx_jar.write_bytes(b"test")
    monkeypatch.setenv("JADX_HOME", str(jadx_home))
    monkeypatch.delenv("DECLIB_JADX_JAR", raising=False)
    monkeypatch.setattr("shutil.which", lambda name: None)

    assert JadxWorkerClient.find_jadx_runtime() == (jadx_jar, "1.5.6")


def test_find_official_jadx_runtime_rejects_old_version(tmp_path, monkeypatch):
    jadx_home = tmp_path / "jadx"
    jadx_jar = jadx_home / "lib" / "jadx-1.5.5-all.jar"
    jadx_jar.parent.mkdir(parents=True)
    jadx_jar.write_bytes(b"test")
    monkeypatch.setenv("JADX_HOME", str(jadx_home))
    monkeypatch.delenv("DECLIB_JADX_JAR", raising=False)
    monkeypatch.setattr("shutil.which", lambda name: None)

    with pytest.raises(RuntimeError, match="too old"):
        JadxWorkerClient.find_jadx_runtime()


def test_resolve_command_uses_thin_bridge_and_official_jadx(
    tmp_path,
    monkeypatch,
):
    java = tmp_path / "java"
    bridge = tmp_path / "declib-jadx-worker.jar"
    jadx = tmp_path / "jadx-1.5.6-all.jar"
    for path in (java, bridge, jadx):
        path.write_bytes(b"test")

    monkeypatch.delenv("DECLIB_JADX_WORKER", raising=False)
    monkeypatch.setenv("DECLIB_JADX_WORKER_OPTS", "-Xmx2g")
    with (
        patch.object(
            JadxWorkerClient,
            "find_jadx_runtime",
            return_value=(jadx, "1.5.6"),
        ),
        patch.object(
            JadxWorkerClient,
            "find_java",
            return_value=(java, 21),
        ),
        patch.object(
            JadxWorkerClient,
            "find_bridge_jar",
            return_value=bridge,
        ),
    ):
        command = JadxWorkerClient.resolve_command(build_if_missing=False)

    assert command == [
        str(java),
        "-Xmx2g",
        "-cp",
        f"{bridge}{os.pathsep}{jadx}",
        JadxWorkerClient.WORKER_MAIN_CLASS,
    ]


def test_runtime_status_reports_missing_optional_runtime(monkeypatch):
    monkeypatch.delenv("DECLIB_JADX_WORKER", raising=False)
    with (
        patch.object(JadxWorkerClient, "find_bridge_jar", return_value=Path("/bridge.jar")),
        patch.object(JadxWorkerClient, "find_java", return_value=(Path("/java"), 21)),
        patch.object(JadxWorkerClient, "find_jadx_runtime", return_value=(None, None)),
    ):
        status = JadxWorkerClient.runtime_status()

    assert status["available"] is False
    assert status["source"] == "official-jadx"
    assert status["reasons"] == ["official JADX runtime was not found"]
