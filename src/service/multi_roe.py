"""
Multi-ROE Specification Manager

Manages multiple ROE specifications for concurrent engagements.
Each engagement has its own ROE spec, rule engine instance, and
audit trail. The manager handles loading, validation, selection,
and lifecycle of ROE specs.
"""

from __future__ import annotations

import threading
import yaml
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..crypto.signer import compute_roe_hash


@dataclass
class ROEEntry:
    """A single loaded ROE specification with metadata."""
    engagement_id: str
    client: str
    roe_spec: dict[str, Any]
    roe_hash: str
    loaded_at: str
    status: str  # "active", "expired", "archived"
    file_path: str | None = None


class MultiROEManager:
    """Manages multiple ROE specifications for concurrent engagements.

    Thread-safe manager that supports loading from files or dicts,
    lookup by engagement ID, lifecycle management (archive/remove),
    and validation of ROE spec structure.
    """

    def __init__(self, roe_dir: str | Path | None = None) -> None:
        """Initialize the manager.

        Args:
            roe_dir: Optional directory path. If provided, all .yaml files
                     in that directory will be loaded on init.
        """
        self._entries: dict[str, ROEEntry] = {}
        self._lock = threading.Lock()

        if roe_dir is not None:
            roe_path = Path(roe_dir)
            if roe_path.is_dir():
                for yaml_file in sorted(roe_path.glob("*.yaml")):
                    self.load_roe(yaml_file)

    def load_roe(self, file_path: str | Path) -> ROEEntry:
        """Load and validate a ROE spec from a YAML file.

        Args:
            file_path: Path to a YAML ROE specification file.

        Returns:
            The created ROEEntry.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the spec is invalid or has a duplicate engagement_id.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"ROE file not found: {path}")

        with open(path, "r") as f:
            raw = yaml.safe_load(f)

        roe_spec = raw.get("roe", raw)
        errors = self._validate(roe_spec)
        if errors:
            raise ValueError(f"Invalid ROE spec in {path}: {'; '.join(errors)}")

        engagement_id = roe_spec["metadata"]["engagement_id"]
        with self._lock:
            if engagement_id in self._entries:
                raise ValueError(
                    f"Duplicate engagement_id '{engagement_id}': "
                    f"already loaded from {self._entries[engagement_id].file_path}"
                )

            entry = ROEEntry(
                engagement_id=engagement_id,
                client=roe_spec.get("metadata", {}).get("client", ""),
                roe_spec=roe_spec,
                roe_hash=compute_roe_hash(roe_spec),
                loaded_at=datetime.now(timezone.utc).isoformat(),
                status="active",
                file_path=str(path),
            )
            self._entries[engagement_id] = entry
        return entry

    def add_roe(self, roe_spec: dict[str, Any]) -> ROEEntry:
        """Add an already-parsed ROE spec.

        Args:
            roe_spec: A parsed ROE specification dict (the content under
                      the 'roe' key, or the full dict with a 'roe' key).

        Returns:
            The created ROEEntry.

        Raises:
            ValueError: If the spec is invalid or has a duplicate engagement_id.
        """
        spec = roe_spec.get("roe", roe_spec)
        errors = self._validate(spec)
        if errors:
            raise ValueError(f"Invalid ROE spec: {'; '.join(errors)}")

        engagement_id = spec["metadata"]["engagement_id"]
        with self._lock:
            if engagement_id in self._entries:
                raise ValueError(
                    f"Duplicate engagement_id '{engagement_id}': already loaded"
                )

            entry = ROEEntry(
                engagement_id=engagement_id,
                client=spec.get("metadata", {}).get("client", ""),
                roe_spec=spec,
                roe_hash=compute_roe_hash(spec),
                loaded_at=datetime.now(timezone.utc).isoformat(),
                status="active",
                file_path=None,
            )
            self._entries[engagement_id] = entry
        return entry

    def get_roe(self, engagement_id: str) -> ROEEntry | None:
        """Look up a ROE entry by engagement ID.

        Returns None if not found.
        """
        with self._lock:
            return self._entries.get(engagement_id)

    def get_active(self) -> list[ROEEntry]:
        """Return all ROE entries with status 'active'."""
        with self._lock:
            return [e for e in self._entries.values() if e.status == "active"]

    def list_all(self) -> list[ROEEntry]:
        """Return all ROE entries regardless of status."""
        with self._lock:
            return list(self._entries.values())

    def archive(self, engagement_id: str) -> None:
        """Mark a ROE entry as archived.

        Raises:
            KeyError: If the engagement_id is not found.
        """
        with self._lock:
            if engagement_id not in self._entries:
                raise KeyError(f"Unknown engagement_id: {engagement_id}")
            self._entries[engagement_id].status = "archived"

    def remove(self, engagement_id: str) -> None:
        """Remove a ROE entry entirely.

        Raises:
            KeyError: If the engagement_id is not found.
        """
        with self._lock:
            if engagement_id not in self._entries:
                raise KeyError(f"Unknown engagement_id: {engagement_id}")
            del self._entries[engagement_id]

    def select(self, engagement_id: str) -> dict[str, Any]:
        """Get the parsed ROE spec for use with ROEGate.

        Args:
            engagement_id: The engagement to select.

        Returns:
            The parsed ROE spec dict.

        Raises:
            KeyError: If the engagement_id is not found.
        """
        with self._lock:
            if engagement_id not in self._entries:
                raise KeyError(f"Unknown engagement_id: {engagement_id}")
            return self._entries[engagement_id].roe_spec

    @staticmethod
    def _validate(roe_spec: dict[str, Any]) -> list[str]:
        """Validate a ROE spec and return a list of error strings.

        Required sections: metadata (with engagement_id), scope, actions.
        """
        errors: list[str] = []

        if "metadata" not in roe_spec:
            errors.append("Missing required section: metadata")
        elif "engagement_id" not in roe_spec.get("metadata", {}):
            errors.append("metadata section missing required field: engagement_id")

        if "scope" not in roe_spec:
            errors.append("Missing required section: scope")

        if "actions" not in roe_spec:
            errors.append("Missing required section: actions")

        return errors
