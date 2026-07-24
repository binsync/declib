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

    WORKER_MAIN_CLASS = "declib.jadxworker.Main"
    TESTED_JADX_VERSION = "1.5.6"
    MINIMUM_JADX_VERSION = (1, 5, 6)
    DEFAULT_JVM_OPTIONS = ("-Xms128m", "-Xmx4g", "-XX:+UseG1GC")

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
        jadx_jar, _ = cls.find_jadx_runtime()
        if jadx_jar is None:
            raise JadxWorkerError(
                "Official JADX runtime not found. Install JADX "
                f"{cls.TESTED_JADX_VERSION} or newer and put `jadx` on PATH, "
                "set JADX_HOME to its installation directory, set "
                "DECLIB_JADX_JAR to its jadx-*-all.jar, or set "
                "DECLIB_JADX_WORKER to a complete worker command."
            )

        java, java_version = cls.find_java()
        if java is None:
            raise JadxWorkerError(
                "Java 17 or newer is required for the JADX backend. Install a "
                "JRE/JDK and put `java` on PATH or set JAVA_HOME."
            )
        if java_version is not None and java_version < 17:
            raise JadxWorkerError(
                f"Java 17 or newer is required for the JADX backend; found "
                f"Java {java_version} at {java}."
            )

        bridge_jar = cls.find_bridge_jar(worker_dir)
        if bridge_jar is None and build_if_missing:
            cls.build_bridge(worker_dir)
            bridge_jar = cls.find_bridge_jar(worker_dir)
        if bridge_jar is None:
            raise JadxWorkerError(
                f"DecLib's JADX bridge is missing under {worker_dir}. Released "
                "wheels include it; from a source checkout run "
                f"`gradle --no-daemon -p {worker_dir} jar`, or set "
                "DECLIB_JADX_WORKER to a complete worker command."
            )

        raw_jvm_options = os.getenv("DECLIB_JADX_WORKER_OPTS")
        jvm_options = (
            shlex.split(raw_jvm_options)
            if raw_jvm_options is not None
            else list(cls.DEFAULT_JVM_OPTIONS)
        )
        return [
            str(java),
            *jvm_options,
            "-cp",
            os.pathsep.join((str(bridge_jar), str(jadx_jar))),
            cls.WORKER_MAIN_CLASS,
        ]

    @classmethod
    def find_bridge_jar(cls, worker_dir: Optional[Path] = None) -> Optional[Path]:
        worker_dir = worker_dir or Path(__file__).with_name("worker")
        candidates = (
            worker_dir / "bridge" / "declib-jadx-worker.jar",
            worker_dir / "build" / "libs" / "declib-jadx-worker.jar",
        )
        return next((path for path in candidates if path.is_file()), None)

    @classmethod
    def find_jadx_runtime(cls) -> tuple[Optional[Path], Optional[str]]:
        override = os.getenv("DECLIB_JADX_JAR")
        if override:
            path = Path(override).expanduser().resolve()
            if not path.is_file():
                raise JadxWorkerError(f"DECLIB_JADX_JAR does not exist: {path}")
            version = cls._version_from_jar(path)
            cls._validate_jadx_version(path, version)
            return path, version

        homes = []
        env_home = os.getenv("JADX_HOME")
        if env_home:
            homes.append(Path(env_home).expanduser())

        jadx_executable = shutil.which("jadx")
        if jadx_executable:
            executable = Path(jadx_executable).expanduser().resolve()
            homes.extend((executable.parent.parent, executable.parent))

        visited = set()
        for home in homes:
            home = home.resolve()
            if home in visited:
                continue
            visited.add(home)
            for lib_dir in (home / "lib", home / "libexec" / "lib", home):
                if not lib_dir.is_dir():
                    continue
                jars = sorted(
                    (
                        *lib_dir.glob("jadx-*-all.jar"),
                        *lib_dir.glob("jadx-all.jar"),
                    ),
                    reverse=True,
                )
                if jars:
                    version = cls._version_from_jar(jars[0])
                    cls._validate_jadx_version(jars[0], version)
                    return jars[0], version
        return None, None

    @classmethod
    def _validate_jadx_version(
        cls,
        path: Path,
        version: Optional[str],
    ) -> None:
        if (
            version is not None
            and cls._version_tuple(version) < cls.MINIMUM_JADX_VERSION
        ):
            raise JadxWorkerError(
                f"JADX {version} at {path} is too old; "
                f"{cls.TESTED_JADX_VERSION} or newer is required."
            )

    @staticmethod
    def _version_from_jar(path: Path) -> Optional[str]:
        prefix = "jadx-"
        suffix = "-all.jar"
        name = path.name
        if not name.startswith(prefix) or not name.endswith(suffix):
            return None
        return name[len(prefix):-len(suffix)]

    @staticmethod
    def _version_tuple(version: str) -> tuple[int, ...]:
        parts = []
        for part in version.split("."):
            digits = "".join(char for char in part if char.isdigit())
            if not digits:
                break
            parts.append(int(digits))
        return tuple(parts)

    @staticmethod
    def find_java() -> tuple[Optional[Path], Optional[int]]:
        java_home = os.getenv("JAVA_HOME")
        candidates = []
        if java_home:
            executable = "java.exe" if os.name == "nt" else "java"
            candidates.append(Path(java_home).expanduser() / "bin" / executable)
        on_path = shutil.which("java")
        if on_path:
            candidates.append(Path(on_path))

        java = next((path.resolve() for path in candidates if path.is_file()), None)
        if java is None:
            return None, None
        try:
            result = subprocess.run(
                [str(java), "-version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return java, None

        first_line = result.stdout.splitlines()[0] if result.stdout else ""
        quoted = first_line.split('"', 2)
        version = quoted[1] if len(quoted) >= 3 else first_line
        first_component = version.split(".", 1)[0]
        if first_component == "1":
            components = version.split(".")
            first_component = components[1] if len(components) > 1 else ""
        digits = "".join(char for char in first_component if char.isdigit())
        return java, int(digits) if digits else None

    @classmethod
    def runtime_status(cls) -> Dict[str, Any]:
        override = os.getenv("DECLIB_JADX_WORKER")
        if override:
            return {
                "available": True,
                "source": "DECLIB_JADX_WORKER",
                "worker_command": override,
                "tested_jadx_version": cls.TESTED_JADX_VERSION,
            }

        bridge = cls.find_bridge_jar()
        java, java_version = cls.find_java()
        try:
            jadx_jar, jadx_version = cls.find_jadx_runtime()
            runtime_error = None
        except JadxWorkerError as exc:
            jadx_jar, jadx_version = None, None
            runtime_error = str(exc)

        reasons = []
        if bridge is None:
            reasons.append("DecLib JADX bridge JAR is missing")
        if java is None:
            reasons.append("Java is not installed")
        elif java_version is not None and java_version < 17:
            reasons.append(f"Java {java_version} is older than Java 17")
        if runtime_error:
            reasons.append(runtime_error)
        elif jadx_jar is None:
            reasons.append("official JADX runtime was not found")

        return {
            "available": not reasons,
            "source": "official-jadx",
            "bridge_jar": str(bridge) if bridge else None,
            "java": str(java) if java else None,
            "java_version": java_version,
            "jadx_jar": str(jadx_jar) if jadx_jar else None,
            "jadx_version": jadx_version,
            "tested_jadx_version": cls.TESTED_JADX_VERSION,
            "reasons": reasons,
        }

    @staticmethod
    def build_bridge(worker_dir: Path) -> None:
        gradle = shutil.which("gradle")
        if gradle is None:
            raise JadxWorkerError(
                "The DecLib JADX bridge is not built, and Gradle is unavailable. "
                "Released wheels include the bridge; source checkouts require "
                "Gradle for this developer build step."
            )
        lock_path = worker_dir / ".build.lock"
        with FileLock(str(lock_path)):
            bridge_jar = worker_dir / "build" / "libs" / "declib-jadx-worker.jar"
            if bridge_jar.exists():
                return
            result = subprocess.run(
                [gradle, "--no-daemon", "jar"],
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
