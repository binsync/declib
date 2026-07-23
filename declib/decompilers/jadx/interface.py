import hashlib
from pathlib import Path
from typing import Dict, List, Optional

from declib.api.artifact_lifter import ArtifactLifter
from declib.api.decompiler_interface import DecompilerInterface
from declib.artifacts import Function

from .worker_client import JadxWorkerClient


class JadxInterface(DecompilerInterface):
    """Headless JADX backend using a transport-private Java worker."""

    def __init__(
        self,
        *,
        worker_executable: Optional[str] = None,
        worker_timeout: float = 120.0,
        **kwargs,
    ):
        if not kwargs.get("binary_path"):
            raise ValueError("JADX requires binary_path for an APK, DEX, JAR, or class input")
        self._worker_executable = worker_executable
        self._worker_timeout = worker_timeout
        self._worker: Optional[JadxWorkerClient] = None
        self._jadx_info: Dict = {}
        self._binary_hash: Optional[str] = None
        # JADX is embedded as a headless library; there is no DecLib GUI plugin
        # mode for this backend.
        kwargs["headless"] = True
        super().__init__(
            name="jadx",
            artifact_lifter=ArtifactLifter(self),
            default_func_prefix="",
            **kwargs,
        )

    def _init_headless_components(self, *args, **kwargs):
        super()._init_headless_components(*args, **kwargs)
        self._worker = JadxWorkerClient(
            executable=self._worker_executable,
            request_timeout=self._worker_timeout,
        )
        try:
            self._jadx_info = self._worker.call(
                "load",
                {"path": str(self._binary_path)},
                timeout=max(self._worker_timeout, 300.0),
            )
        except Exception:
            self._worker.close()
            self._worker = None
            raise

    def _deinit_headless_components(self):
        if self._worker is not None:
            self._worker.close()
            self._worker = None

    @property
    def binary_base_addr(self) -> int:
        return 0

    @property
    def binary_hash(self) -> str:
        if self._binary_hash is None:
            digest = hashlib.md5()
            with Path(self._binary_path).open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            self._binary_hash = digest.hexdigest()
        return self._binary_hash

    @property
    def binary_arch(self) -> str:
        return "dalvik"

    @property
    def default_pointer_size(self) -> int:
        return 4

    def managed_capabilities(self) -> Dict:
        return dict(self._jadx_info)

    def managed_list_classes(
        self,
        filter: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Dict]:
        return self._call("list_classes", {"filter": filter, "limit": limit})

    def managed_list_methods(
        self,
        class_ref: Optional[str] = None,
        filter: Optional[str] = None,
        limit: int = 2000,
    ) -> List[Dict]:
        return self._call(
            "list_methods",
            {"class_ref": class_ref, "filter": filter, "limit": limit},
        )

    def managed_list_fields(
        self,
        class_ref: Optional[str] = None,
        filter: Optional[str] = None,
        limit: int = 2000,
    ) -> List[Dict]:
        return self._call(
            "list_fields",
            {"class_ref": class_ref, "filter": filter, "limit": limit},
        )

    def managed_class_source(self, ref: str) -> Dict:
        return self._call("class_source", {"ref": ref})

    def managed_method_source(self, ref: str) -> Dict:
        return self._call("method_source", {"ref": ref})

    def managed_class_xrefs(self, ref: str) -> List[Dict]:
        return self._call("class_xrefs", {"ref": ref})

    def managed_method_xrefs(self, ref: str, direction: str = "both") -> Dict:
        return self._call("method_xrefs", {"ref": ref, "direction": direction})

    def managed_field_xrefs(self, ref: str) -> List[Dict]:
        return self._call("field_xrefs", {"ref": ref})

    def managed_list_resources(
        self,
        filter: Optional[str] = None,
        limit: int = 2000,
    ) -> List[Dict]:
        return self._call("list_resources", {"filter": filter, "limit": limit})

    def managed_get_resource(self, path: str, max_bytes: int = 1024 * 1024) -> Dict:
        return self._call(
            "get_resource",
            {"path": path, "max_bytes": max_bytes},
        )

    def managed_get_manifest(self) -> Dict:
        return self._call("get_manifest")

    def fast_get_function(self, func_addr) -> Optional[Function]:
        return None

    def get_func_size(self, func_addr) -> int:
        return 0

    def get_func_containing(self, addr: int) -> Optional[Function]:
        return None

    def _functions(self) -> Dict[int, Function]:
        # Managed methods deliberately use opaque descriptors instead of fake
        # native addresses. See managed_list_methods().
        return {}

    def _call(self, method: str, params: Optional[Dict] = None):
        if self._worker is None:
            raise RuntimeError("JADX worker is not running")
        return self._worker.call(method, params)
