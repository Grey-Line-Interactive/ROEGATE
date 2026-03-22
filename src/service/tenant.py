"""
Multi-Tenant Architecture for ROE Gate

Provides tenant isolation for MSSP/OEM deployments where multiple
clients share the same Gate infrastructure. Each tenant gets:
- Isolated ROE specifications
- Separate audit trails
- Independent signing keys
- Tenant-scoped API access
"""

from __future__ import annotations

import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Tenant:
    tenant_id: str
    name: str
    created_at: str
    status: str  # "active", "suspended", "archived"
    config: dict
    signing_key: bytes

    # Per-tenant counters
    audit_event_count: int = 0
    evaluation_count: int = 0


_thread_local = threading.local()


class TenantContext:
    """Context manager that sets thread-local tenant context."""

    def __init__(self, tenant: Tenant) -> None:
        self._tenant = tenant
        self._previous: Tenant | None = None

    def __enter__(self) -> Tenant:
        self._previous = getattr(_thread_local, "current_tenant", None)
        _thread_local.current_tenant = self._tenant
        return self._tenant

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        _thread_local.current_tenant = self._previous

    @staticmethod
    def current_tenant() -> Tenant | None:
        """Return the tenant bound to this thread, or None."""
        return getattr(_thread_local, "current_tenant", None)


class TenantManager:
    """Thread-safe manager for tenant lifecycle operations."""

    def __init__(self) -> None:
        self._tenants: dict[str, Tenant] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_tenant(self, name: str, config: dict | None = None) -> Tenant:
        """Create a tenant with a unique id and signing key."""
        tenant_id = uuid.uuid4().hex[:12]
        signing_key = os.urandom(32)
        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            created_at=datetime.now(timezone.utc).isoformat(),
            status="active",
            config=config or {},
            signing_key=signing_key,
        )
        with self._lock:
            self._tenants[tenant_id] = tenant
        return tenant

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        with self._lock:
            return self._tenants.get(tenant_id)

    def list_tenants(self) -> list[Tenant]:
        with self._lock:
            return list(self._tenants.values())

    # ------------------------------------------------------------------
    # Status transitions
    # ------------------------------------------------------------------

    def suspend_tenant(self, tenant_id: str) -> None:
        with self._lock:
            tenant = self._tenants.get(tenant_id)
            if tenant is None:
                raise KeyError(f"Tenant {tenant_id} not found")
            tenant.status = "suspended"

    def activate_tenant(self, tenant_id: str) -> None:
        with self._lock:
            tenant = self._tenants.get(tenant_id)
            if tenant is None:
                raise KeyError(f"Tenant {tenant_id} not found")
            tenant.status = "active"

    def archive_tenant(self, tenant_id: str) -> None:
        with self._lock:
            tenant = self._tenants.get(tenant_id)
            if tenant is None:
                raise KeyError(f"Tenant {tenant_id} not found")
            tenant.status = "archived"

    def remove_tenant(self, tenant_id: str) -> None:
        with self._lock:
            if tenant_id not in self._tenants:
                raise KeyError(f"Tenant {tenant_id} not found")
            del self._tenants[tenant_id]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_tenant_stats(self, tenant_id: str) -> dict:
        """Return usage statistics for a tenant."""
        with self._lock:
            tenant = self._tenants.get(tenant_id)
            if tenant is None:
                raise KeyError(f"Tenant {tenant_id} not found")
            return {
                "tenant_id": tenant.tenant_id,
                "name": tenant.name,
                "status": tenant.status,
                "created_at": tenant.created_at,
                "audit_event_count": tenant.audit_event_count,
                "evaluation_count": tenant.evaluation_count,
            }
