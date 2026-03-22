"""Tests for Multi-Tenant Architecture."""

import threading

import pytest

from src.service.tenant import Tenant, TenantContext, TenantManager


class TestTenantCreation:
    def test_create_tenant(self) -> None:
        mgr = TenantManager()
        tenant = mgr.create_tenant("Acme Corp")
        assert tenant.name == "Acme Corp"
        assert tenant.status == "active"
        assert len(tenant.tenant_id) == 12
        assert tenant.created_at != ""
        assert tenant.config == {}

    def test_create_tenant_with_config(self) -> None:
        mgr = TenantManager()
        tenant = mgr.create_tenant("Acme Corp", config={"max_agents": 5})
        assert tenant.config == {"max_agents": 5}

    def test_each_tenant_gets_unique_signing_key(self) -> None:
        mgr = TenantManager()
        t1 = mgr.create_tenant("Tenant A")
        t2 = mgr.create_tenant("Tenant B")
        assert t1.signing_key != t2.signing_key
        assert len(t1.signing_key) == 32
        assert len(t2.signing_key) == 32

    def test_each_tenant_gets_unique_id(self) -> None:
        mgr = TenantManager()
        t1 = mgr.create_tenant("Tenant A")
        t2 = mgr.create_tenant("Tenant B")
        assert t1.tenant_id != t2.tenant_id


class TestTenantLookup:
    def test_get_tenant(self) -> None:
        mgr = TenantManager()
        created = mgr.create_tenant("Acme Corp")
        fetched = mgr.get_tenant(created.tenant_id)
        assert fetched is not None
        assert fetched.tenant_id == created.tenant_id
        assert fetched.name == "Acme Corp"

    def test_get_tenant_returns_none_for_unknown(self) -> None:
        mgr = TenantManager()
        assert mgr.get_tenant("nonexistent") is None

    def test_list_tenants(self) -> None:
        mgr = TenantManager()
        mgr.create_tenant("A")
        mgr.create_tenant("B")
        mgr.create_tenant("C")
        tenants = mgr.list_tenants()
        assert len(tenants) == 3
        names = {t.name for t in tenants}
        assert names == {"A", "B", "C"}


class TestTenantStatusTransitions:
    def test_suspend_tenant(self) -> None:
        mgr = TenantManager()
        t = mgr.create_tenant("Acme")
        mgr.suspend_tenant(t.tenant_id)
        assert mgr.get_tenant(t.tenant_id).status == "suspended"

    def test_activate_tenant(self) -> None:
        mgr = TenantManager()
        t = mgr.create_tenant("Acme")
        mgr.suspend_tenant(t.tenant_id)
        mgr.activate_tenant(t.tenant_id)
        assert mgr.get_tenant(t.tenant_id).status == "active"

    def test_archive_tenant(self) -> None:
        mgr = TenantManager()
        t = mgr.create_tenant("Acme")
        mgr.archive_tenant(t.tenant_id)
        assert mgr.get_tenant(t.tenant_id).status == "archived"

    def test_suspend_unknown_tenant_raises(self) -> None:
        mgr = TenantManager()
        with pytest.raises(KeyError):
            mgr.suspend_tenant("nonexistent")


class TestTenantRemoval:
    def test_remove_tenant(self) -> None:
        mgr = TenantManager()
        t = mgr.create_tenant("Acme")
        mgr.remove_tenant(t.tenant_id)
        assert mgr.get_tenant(t.tenant_id) is None
        assert len(mgr.list_tenants()) == 0

    def test_remove_unknown_tenant_raises(self) -> None:
        mgr = TenantManager()
        with pytest.raises(KeyError):
            mgr.remove_tenant("nonexistent")


class TestTenantContext:
    def test_context_manager_sets_current_tenant(self) -> None:
        mgr = TenantManager()
        tenant = mgr.create_tenant("Acme")
        assert TenantContext.current_tenant() is None
        with TenantContext(tenant) as ctx:
            assert ctx.tenant_id == tenant.tenant_id
            assert TenantContext.current_tenant() is tenant
        assert TenantContext.current_tenant() is None

    def test_context_thread_local_isolation(self) -> None:
        mgr = TenantManager()
        t1 = mgr.create_tenant("Tenant A")
        t2 = mgr.create_tenant("Tenant B")

        results: dict[str, str | None] = {}
        barrier = threading.Barrier(2)

        def worker(name: str, tenant: Tenant) -> None:
            with TenantContext(tenant):
                barrier.wait(timeout=5)
                current = TenantContext.current_tenant()
                results[name] = current.tenant_id if current else None

        thread1 = threading.Thread(target=worker, args=("t1", t1))
        thread2 = threading.Thread(target=worker, args=("t2", t2))
        thread1.start()
        thread2.start()
        thread1.join(timeout=5)
        thread2.join(timeout=5)

        assert results["t1"] == t1.tenant_id
        assert results["t2"] == t2.tenant_id

    def test_nested_context(self) -> None:
        mgr = TenantManager()
        outer = mgr.create_tenant("Outer")
        inner = mgr.create_tenant("Inner")
        with TenantContext(outer):
            assert TenantContext.current_tenant() is outer
            with TenantContext(inner):
                assert TenantContext.current_tenant() is inner
            assert TenantContext.current_tenant() is outer
        assert TenantContext.current_tenant() is None


class TestTenantStats:
    def test_get_tenant_stats(self) -> None:
        mgr = TenantManager()
        t = mgr.create_tenant("Acme")
        t.audit_event_count = 15
        t.evaluation_count = 42
        stats = mgr.get_tenant_stats(t.tenant_id)
        assert stats["tenant_id"] == t.tenant_id
        assert stats["name"] == "Acme"
        assert stats["audit_event_count"] == 15
        assert stats["evaluation_count"] == 42

    def test_stats_unknown_tenant_raises(self) -> None:
        mgr = TenantManager()
        with pytest.raises(KeyError):
            mgr.get_tenant_stats("nonexistent")
