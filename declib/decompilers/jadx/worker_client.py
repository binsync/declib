import json
import os
import queue
import shlex
import shutil
import subprocess
import threading
from collections import deque
from pathlib import Path
from typing import Any, Dict, Optional

from filelock import FileLock


class JadxWorkerError(RuntimeError):
    """Raised when the Java JADX worker rejects a request or exits."""


class JadxWorkerClient:
    """Synchronous JSONL client for the long-lived Java JADX worker."""

    def __init__(
        self,
        *,
        executable: Optional[str] = None,
        request_timeout: float = 120.0,
        build_if_missing: bool = True,
    ):
        self.request_timeout = request_timeout
        self._request_lock = threading.Lock()
        self._responses: queue.Queue = queue.Queue()
        self._stderr_tail = deque(maxlen=100)
        self._next_id = 1
        self._closed = False

        command = self.resolve_command(
            executable=executable,
            build_if_missing=build_if_missing,
        )
        self._process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._stdout_thread = threading.Thread(
            target=self._read_stdout,
            name="declib-jadx-stdout",
            daemon=True,
        )
        self._stderr_thread = threading.Thread(
            target=self._read_stderr,
            name="declib-jadx-stderr",
            daemon=True,
        )
        self._stdout_thread.start()
        self._stderr_thread.start()
        self.call("ping", timeout=15.0)

    @classmethod
    def resolve_command(
        cls,
        *,
        executable: Optional[str] = None,
        build_if_missing: bool = True,
    ) -> list[str]:
        override = executable or os.getenv("DECLIB_JADX_WORKER")
        if override:
            command = shlex.split(override)
            if not command:
                raise JadxWorkerError("DECLIB_JADX_WORKER is empty")
            return command

        worker_dir = Path(__file__).with_name("worker")
        script_name = "declib-jadx-worker.bat" if os.name == "nt" else "declib-jadx-worker"
        script = worker_dir / "build" / "install" / "declib-jadx-worker" / "bin" / script_name
        if not script.exists() and build_if_missing:
            cls.build(worker_dir)
        if not script.exists():
            raise JadxWorkerError(
                f"JADX worker is not built at {script}. Run "
                f"`gradle --no-daemon installDist` in {worker_dir}, or set "
                "DECLIB_JADX_WORKER to a prebuilt worker executable."
            )
        return [str(script)]

    @staticmethod
    def build(worker_dir: Path) -> None:
        gradle = shutil.which("gradle")
        if gradle is None:
            raise JadxWorkerError(
                "Gradle is required to build the JADX worker. Install Gradle or "
                "set DECLIB_JADX_WORKER to a prebuilt worker executable."
            )
        lock_path = worker_dir / ".build.lock"
        with FileLock(str(lock_path)):
            script_name = "declib-jadx-worker.bat" if os.name == "nt" else "declib-jadx-worker"
            script = (
                worker_dir
                / "build"
                / "install"
                / "declib-jadx-worker"
                / "bin"
                / script_name
            )
            if script.exists():
                return
            result = subprocess.run(
                [gradle, "--no-daemon", "installDist"],
                cwd=worker_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                timeout=300,
                check=False,
            )
            if result.returncode != 0:
                raise JadxWorkerError(
                    "Failed to build the JADX worker:\n" + result.stdout[-8000:]
                )

    def call(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        timeout: Optional[float] = None,
    ) -> Any:
        if self._closed:
            raise JadxWorkerError("JADX worker is closed")
        with self._request_lock:
            if self._process.poll() is not None:
                raise self._exit_error()
            request_id = self._next_id
            self._next_id += 1
            request = {
                "id": request_id,
                "method": method,
                "params": params or {},
            }
            assert self._process.stdin is not None
            try:
                self._process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
                self._process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise self._exit_error() from exc

            wait_timeout = self.request_timeout if timeout is None else timeout
            try:
                response = self._responses.get(timeout=wait_timeout)
            except queue.Empty as exc:
                self._terminate_process()
                raise JadxWorkerError(
                    f"JADX worker timed out after {wait_timeout:g}s while handling "
                    f"{method!r} and was terminated; reload the input to retry"
                ) from exc
            if isinstance(response, BaseException):
                raise response
            if response.get("id") != request_id:
                raise JadxWorkerError(
                    f"JADX worker response ID mismatch: expected {request_id}, "
                    f"got {response.get('id')}"
                )
            error = response.get("error")
            if error:
                error_type = error.get("type", "WorkerError")
                message = error.get("message", "Unknown worker error")
                if error_type == "IllegalArgumentException":
                    raise ValueError(message)
                raise JadxWorkerError(f"{error_type}: {message}")
            return response.get("result")

    def close(self) -> None:
        if self._closed:
            return
        try:
            if self._process.poll() is None:
                try:
                    self.call("shutdown", timeout=10.0)
                except Exception:
                    pass
        finally:
            self._terminate_process()

    def _read_stdout(self) -> None:
        assert self._process.stdout is not None
        try:
            for line in self._process.stdout:
                if not line.strip():
                    continue
                try:
                    self._responses.put(json.loads(line))
                except json.JSONDecodeError as exc:
                    self._responses.put(
                        JadxWorkerError(
                            f"JADX worker emitted invalid JSON: {line.rstrip()!r}"
                        )
                    )
                    return
        finally:
            if not self._closed:
                self._responses.put(self._exit_error())

    def _read_stderr(self) -> None:
        assert self._process.stderr is not None
        for line in self._process.stderr:
            self._stderr_tail.append(line.rstrip())

    def _exit_error(self) -> JadxWorkerError:
        status = self._process.poll()
        detail = "\n".join(self._stderr_tail)
        message = f"JADX worker exited unexpectedly with status {status}"
        if detail:
            message += "\nWorker stderr tail:\n" + detail
        return JadxWorkerError(message)

    def _terminate_process(self) -> None:
        self._closed = True
        if self._process.stdin is not None and not self._process.stdin.closed:
            self._process.stdin.close()
        if self._process.poll() is not None:
            return
        try:
            self._process.wait(timeout=5.0)
            return
        except subprocess.TimeoutExpired:
            self._process.terminate()
        try:
            self._process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=2.0)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
