"""Tests for the RBAC module."""

import pytest

from src.auth.rbac import (
    ROLE_PERMISSIONS,
    OIDCProvider,
    Permission,
    RBACManager,
    Role,
    SAMLProvider,
)


@pytest.fixture
def manager() -> RBACManager:
    return RBACManager()


# ---- User creation ----

class TestUserCreation:
    def test_create_admin_user(self, manager: RBACManager) -> None:
        user = manager.add_user("alice", Role.ADMIN, api_key="key-alice")
        assert user.username == "alice"
        assert user.role == Role.ADMIN
        assert user.api_key_hash is not None
        assert user.user_id

    def test_create_agent_user(self, manager: RBACManager) -> None:
        user = manager.add_user("bot-1", Role.AGENT, api_key="key-bot")
        assert user.username == "bot-1"
        assert user.role == Role.AGENT

    def test_create_user_without_api_key(self, manager: RBACManager) -> None:
        user = manager.add_user("viewer1", Role.VIEWER)
        assert user.api_key_hash is None

    def test_duplicate_username_raises(self, manager: RBACManager) -> None:
        manager.add_user("alice", Role.ADMIN)
        with pytest.raises(ValueError, match="already exists"):
            manager.add_user("alice", Role.VIEWER)


# ---- Authentication ----

class TestAuthentication:
    def test_authenticate_valid_key(self, manager: RBACManager) -> None:
        manager.add_user("alice", Role.ADMIN, api_key="secret-key")
        user = manager.authenticate("secret-key")
        assert user is not None
        assert user.username == "alice"

    def test_authenticate_invalid_key_returns_none(self, manager: RBACManager) -> None:
        manager.add_user("alice", Role.ADMIN, api_key="secret-key")
        assert manager.authenticate("wrong-key") is None

    def test_authenticate_no_users_returns_none(self, manager: RBACManager) -> None:
        assert manager.authenticate("anything") is None


# ---- Authorization / permissions ----

class TestAuthorization:
    def test_admin_has_all_permissions(self, manager: RBACManager) -> None:
        user = manager.add_user("admin", Role.ADMIN)
        for perm in Permission:
            assert manager.authorize(user, perm), f"Admin should have {perm}"

    def test_agent_can_evaluate_and_execute(self, manager: RBACManager) -> None:
        user = manager.add_user("bot", Role.AGENT)
        assert manager.authorize(user, Permission.EVALUATE)
        assert manager.authorize(user, Permission.EXECUTE)

    def test_agent_cannot_halt_or_manage(self, manager: RBACManager) -> None:
        user = manager.add_user("bot", Role.AGENT)
        assert not manager.authorize(user, Permission.HALT)
        assert not manager.authorize(user, Permission.MANAGE_USERS)
        assert not manager.authorize(user, Permission.MANAGE_ROE)

    def test_viewer_cannot_halt_or_resume(self, manager: RBACManager) -> None:
        user = manager.add_user("reader", Role.VIEWER)
        assert not manager.authorize(user, Permission.HALT)
        assert not manager.authorize(user, Permission.RESUME)
        assert not manager.authorize(user, Permission.EXECUTE)

    def test_operator_can_halt_but_not_manage_users(self, manager: RBACManager) -> None:
        user = manager.add_user("ops", Role.OPERATOR)
        assert manager.authorize(user, Permission.HALT)
        assert manager.authorize(user, Permission.RESUME)
        assert not manager.authorize(user, Permission.MANAGE_USERS)
        assert not manager.authorize(user, Permission.MANAGE_ROE)


# ---- check_access (combined auth+authz) ----

class TestCheckAccess:
    def test_check_access_granted(self, manager: RBACManager) -> None:
        manager.add_user("admin", Role.ADMIN, api_key="admin-key")
        allowed, reason = manager.check_access("admin-key", Permission.MANAGE_USERS)
        assert allowed is True
        assert "granted" in reason.lower()

    def test_check_access_bad_key(self, manager: RBACManager) -> None:
        allowed, reason = manager.check_access("bogus", Permission.EVALUATE)
        assert allowed is False
        assert "Authentication failed" in reason

    def test_check_access_insufficient_permissions(self, manager: RBACManager) -> None:
        manager.add_user("bot", Role.AGENT, api_key="agent-key")
        allowed, reason = manager.check_access("agent-key", Permission.HALT)
        assert allowed is False
        assert "Authorization denied" in reason


# ---- User management ----

class TestUserManagement:
    def test_remove_user(self, manager: RBACManager) -> None:
        user = manager.add_user("temp", Role.VIEWER, api_key="temp-key")
        manager.remove_user(user.user_id)
        assert manager.get_user(user.user_id) is None
        assert manager.authenticate("temp-key") is None

    def test_remove_nonexistent_user_raises(self, manager: RBACManager) -> None:
        with pytest.raises(KeyError):
            manager.remove_user("no-such-id")

    def test_update_role(self, manager: RBACManager) -> None:
        user = manager.add_user("ops", Role.VIEWER)
        assert not manager.authorize(user, Permission.HALT)
        manager.update_role(user.user_id, Role.OPERATOR)
        assert manager.authorize(user, Permission.HALT)

    def test_update_role_nonexistent_raises(self, manager: RBACManager) -> None:
        with pytest.raises(KeyError):
            manager.update_role("no-such-id", Role.ADMIN)

    def test_list_users(self, manager: RBACManager) -> None:
        manager.add_user("a", Role.ADMIN)
        manager.add_user("b", Role.VIEWER)
        manager.add_user("c", Role.AGENT)
        users = manager.list_users()
        assert len(users) == 3
        names = {u.username for u in users}
        assert names == {"a", "b", "c"}

    def test_get_user_by_username(self, manager: RBACManager) -> None:
        manager.add_user("alice", Role.ADMIN)
        user = manager.get_user_by_username("alice")
        assert user is not None
        assert user.username == "alice"
        assert manager.get_user_by_username("nobody") is None


# ---- SSO stubs ----

class TestSSOStubs:
    def test_saml_provider_raises(self) -> None:
        provider = SAMLProvider(idp_metadata_url="https://idp.example.com/metadata")
        with pytest.raises(NotImplementedError, match="SAML SSO"):
            provider.validate_token("token")
        with pytest.raises(NotImplementedError, match="SAML SSO"):
            provider.get_user_role({})

    def test_oidc_provider_raises(self) -> None:
        provider = OIDCProvider(
            issuer_url="https://auth.example.com",
            client_id="client",
            client_secret="secret",
        )
        with pytest.raises(NotImplementedError, match="OIDC SSO"):
            provider.validate_token("token")
        with pytest.raises(NotImplementedError, match="OIDC SSO"):
            provider.get_user_role({})


# ---- Role-permission mapping sanity ----

class TestRolePermissions:
    def test_all_roles_have_mapping(self) -> None:
        for role in Role:
            assert role in ROLE_PERMISSIONS

    def test_agent_permissions_are_minimal(self) -> None:
        assert ROLE_PERMISSIONS[Role.AGENT] == {Permission.EVALUATE, Permission.EXECUTE}
