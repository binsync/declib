"""
Server registry for declib DecompilerServer instances.

Each running server writes a small JSON descriptor into a shared registry
directory so that the `decompiler` CLI (and DecompilerClient.discover) can
find, filter, and connect to the right server instance. Stale records
(servers whose process has exited or whose socket has vanished) are pruned
on read.
"""
import json
import logging
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import psutil
from platformdirs import user_state_dir

_l = logging.getLogger(__name__)


def _registry_dir() -> Path:
    """Return the registry directory, creating it if missing."""
    env_override = os.environ.get("DECLIB_SERVER_REGISTRY")
    if env_override:
        path = Path(env_override)
    else:
        path = Path(user_state_dir("declib")) / "servers"
    path.mkdir(parents=True, exist_ok=True)
    return path


def new_server_id() -> str:
    """Generate a short unique ID for a new server."""
    return uuid.uuid4().hex[:10]


def default_socket_path(server_id: str) -> str:
    """Compute a default socket path for a server with the given ID."""
    temp_dir = Path(tempfile.gettempdir()) / f"declib_server_{server_id}"
    temp_dir.mkdir(parents=True, exist_ok=True)
    return str(temp_dir / "decompiler.sock")


def registry_path(server_id: str) -> Path:
    return _registry_dir() / f"{server_id}.json"


def register_server(info: Dict) -> Path:
    """Write a server descriptor into the registry. Required keys: id, socket_path."""
    server_id = info["id"]
    path = registry_path(server_id)
    payload = dict(info)
    payload.setdefault("started_at", time.time())
    payload.setdefault("pid", os.getpid())
    tmp_path = path.with_suffix(".json.tmp")
    with open(tmp_path, "w") as f:
        json.dump(payload, f, indent=2, default=str)
    os.replace(tmp_path, path)
    return path


def unregister_server(server_id: str) -> bool:
    path = registry_path(server_id)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def _is_record_live(record: Dict) -> bool:
    pid = record.get("pid")
    socket_path = record.get("socket_path")
    if not socket_path or not os.path.exists(socket_path):
        return False
    if pid is not None:
        try:
            if not psutil.pid_exists(int(pid)):
                return False
        except Exception:
            return False
    return True


def list_servers(prune_stale: bool = True) -> List[Dict]:
    """Return all server records, optionally dropping and removing stale entries."""
    records: List[Dict] = []
    try:
        entries = sorted(_registry_dir().glob("*.json"))
    except FileNotFoundError:
        return []

    for entry in entries:
        try:
            with open(entry, "r") as f:
                record = json.load(f)
        except Exception as exc:
            _l.debug("Failed to read server registry file %s: %s", entry, exc)
            continue

        if prune_stale and not _is_record_live(record):
            try:
                entry.unlink()
            except FileNotFoundError:
                pass
            except Exception as exc:
                _l.debug("Failed to remove stale registry entry %s: %s", entry, exc)
            continue

        records.append(record)
    return records


def find_server(
    server_id: Optional[str] = None,
    binary_path: Optional[str] = None,
    binary_hash: Optional[str] = None,
    backend: Optional[str] = None,
) -> Optional[Dict]:
    """Return the first server record matching all provided filters, else None."""
    binary_path_resolved = str(Path(binary_path).expanduser().resolve()) if binary_path else None
    for record in list_servers():
        if server_id and record.get("id") != server_id:
            continue
        if binary_path_resolved:
            record_path = record.get("binary_path")
            if not record_path:
                continue
            try:
                if str(Path(record_path).expanduser().resolve()) != binary_path_resolved:
                    continue
            except Exception:
                if record_path != binary_path_resolved:
                    continue
        if binary_hash and record.get("binary_hash") != binary_hash:
            continue
        if backend and record.get("backend") != backend:
            continue
        return record
    return None


def find_servers(
    binary_path: Optional[str] = None,
    binary_hash: Optional[str] = None,
    backend: Optional[str] = None,
) -> List[Dict]:
    """Return all server records matching the provided filters."""
    matches: List[Dict] = []
    binary_path_resolved = str(Path(binary_path).expanduser().resolve()) if binary_path else None
    for record in list_servers():
        if binary_path_resolved:
            record_path = record.get("binary_path")
            if not record_path:
                continue
            try:
                if str(Path(record_path).expanduser().resolve()) != binary_path_resolved:
                    continue
            except Exception:
                if record_path != binary_path_resolved:
                    continue
        if binary_hash and record.get("binary_hash") != binary_hash:
            continue
        if backend and record.get("backend") != backend:
            continue
        matches.append(record)
    return matches
