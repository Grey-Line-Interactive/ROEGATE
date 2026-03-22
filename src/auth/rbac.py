from __future__ import annotations

"""
Role-Based Access Control (RBAC) for ROE Gate

Controls who can perform administrative actions on the Gate Service:
- View audit logs
- Trigger emergency halt
- Resume halted sessions
- Load/modify ROE specifications
- View/export compliance reports

Roles:
- admin: Full access (all operations)
- operator: Can evaluate, execute, halt, resume, view audit/stats
- viewer: Read-only access (stats, audit, health)
- agent: Can only evaluate and execute (the AI agent's role)
"""

import hashlib
import threading
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Role(Enum):
    """Roles available in the ROE Gate RBAC system."""
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    AGENT = "agent"


class Permission(Enum):
    """Permissions that can be granted to roles."""
    EVALUATE = "evaluate"
    EXECUTE = "execute"
    VIEW_STATS = "view_stats"
    VIEW_AUDIT = "view_audit"
    HALT = "halt"
    RESUME = "resume"
    MANAGE_ROE = "manage_roe"
    EXPORT_REPORTS = "export_reports"
    MANAGE_USERS = "manage_users"


ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.ADMIN: set(Permission),
    Role.OPERATOR: {
        Permission.EVALUATE,
        Permission.EXECUTE,
        Permission.VIEW_STATS,
        Permission.VIEW_AUDIT,
        Permission.HALT,
        Permission.RESUME,
        Permission.EXPORT_REPORTS,
    },
    Role.VIEWER: {
        Permission.VIEW_STATS,
        Permission.VIEW_AUDIT,
    },
    Role.AGENT: {
        Permission.EVALUATE,
        Permission.EXECUTE,
    },
}


@dataclass
class User:
    """A user in the RBAC system."""
    user_id: str
    username: str
    role: Role
    created_at: str
    api_key_hash: str | None = None


class RBACManager:
    """Thread-safe in-memory RBAC manager for ROE Gate."""

    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._api_key_index: dict[str, str] = {}  # hash -> user_id
        self._lock = threading.Lock()

    @staticmethod
    def _hash_api_key(api_key: str) -> str:
        return hashlib.sha256(api_key.encode()).hexdigest()

    def add_user(self, username: str, role: Role, api_key: str | None = None) -> User:
        """Create a new user. Raises ValueError if username already exists."""
        with self._lock:
            for u in self._users.values():
                if u.username == username:
                    raise ValueError(f"Username '{username}' already exists")

            user_id = str(uuid.uuid4())
            api_key_hash = self._hash_api_key(api_key) if api_key else None

            user = User(
                user_id=user_id,
                username=username,
                role=role,
                created_at=datetime.now(timezone.utc).isoformat(),
                api_key_hash=api_key_hash,
            )
            self._users[user_id] = user

            if api_key_hash:
                self._api_key_index[api_key_hash] = user_id

            return user

    def remove_user(self, user_id: str) -> None:
        """Remove a user by ID. Raises KeyError if not found."""
        with self._lock:
            user = self._users.pop(user_id, None)
            if user is None:
                raise KeyError(f"User '{user_id}' not found")
            if user.api_key_hash and user.api_key_hash in self._api_key_index:
                del self._api_key_index[user.api_key_hash]

    def get_user(self, user_id: str) -> User | None:
        """Look up a user by ID."""
        with self._lock:
            return self._users.get(user_id)

    def get_user_by_username(self, username: str) -> User | None:
        """Look up a user by username."""
        with self._lock:
            for u in self._users.values():
                if u.username == username:
                    return u
            return None

    def authenticate(self, api_key: str) -> User | None:
        """Authenticate by API key. Returns the User or None."""
        key_hash = self._hash_api_key(api_key)
        with self._lock:
            user_id = self._api_key_index.get(key_hash)
            if user_id is None:
                return None
            return self._users.get(user_id)

    def authorize(self, user: User, permission: Permission) -> bool:
        """Check whether a user's role grants the given permission."""
        return permission in ROLE_PERMISSIONS.get(user.role, set())

    def check_access(self, api_key: str, permission: Permission) -> tuple[bool, str]:
        """Combined authenticate + authorize. Returns (allowed, reason)."""
        user = self.authenticate(api_key)
        if user is None:
            return False, "Authentication failed: invalid API key"
        if not self.authorize(user, permission):
            return False, (
                f"Authorization denied: role '{user.role.value}' "
                f"does not have '{permission.value}' permission"
            )
        return True, "Access granted"

    def list_users(self) -> list[User]:
        """Return a list of all users."""
        with self._lock:
            return list(self._users.values())

    def update_role(self, user_id: str, new_role: Role) -> None:
        """Change a user's role. Raises KeyError if not found."""
        with self._lock:
            user = self._users.get(user_id)
            if user is None:
                raise KeyError(f"User '{user_id}' not found")
            user.role = new_role


# ---------------------------------------------------------------------------
# SSO Provider interfaces (stubs for enterprise integration)
# ---------------------------------------------------------------------------

class SSOProvider(ABC):
    """Abstract base class for SSO providers."""

    @abstractmethod
    def validate_token(self, token: str) -> dict | None:
        """Validate an SSO token and return user info, or None on failure."""

    @abstractmethod
    def get_user_role(self, user_info: dict) -> Role:
        """Map SSO claims/attributes to an RBAC Role."""


class SAMLProvider(SSOProvider):
    """SAML 2.0 SSO provider stub."""

    def __init__(self, idp_metadata_url: str) -> None:
        self.idp_metadata_url = idp_metadata_url

    def validate_token(self, token: str) -> dict | None:
        raise NotImplementedError("SAML SSO requires enterprise configuration")

    def get_user_role(self, user_info: dict) -> Role:
        raise NotImplementedError("SAML SSO requires enterprise configuration")


class OIDCProvider(SSOProvider):
    """OpenID Connect SSO provider stub."""

    def __init__(self, issuer_url: str, client_id: str, client_secret: str) -> None:
        self.issuer_url = issuer_url
        self.client_id = client_id
        self.client_secret = client_secret

    def validate_token(self, token: str) -> dict | None:
        raise NotImplementedError("OIDC SSO requires enterprise configuration")

    def get_user_role(self, user_info: dict) -> Role:
        raise NotImplementedError("OIDC SSO requires enterprise configuration")
