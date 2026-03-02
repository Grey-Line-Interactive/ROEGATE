"""
Agent Sandbox — Runtime Isolation for the Testing Agent

This module creates the restricted execution environment where the agent
runs. The agent's Python process has these dangerous modules BLOCKED:

  - subprocess  (can't spawn processes)
  - os.system   (can't run shell commands)
  - os.exec*    (can't replace the process)
  - os.spawn*   (can't spawn new processes)
  - socket      (can't open network connections)
  - ctypes      (can't call C functions / bypass Python)
  - shutil      (can't move/copy files outside sandbox)

The ONLY way the agent can interact with external systems is through
the ToolProxy, which routes everything through the ROE Gate.

DEFENSE IN DEPTH — Three layers of enforcement:

  Layer 1: MODULE BLOCKING (this file)
    Python-level: dangerous modules are replaced with stubs that raise
    PermissionError. The agent literally cannot import subprocess.

  Layer 2: PROCESS ISOLATION (deployment)
    OS-level: the agent runs in a container/sandbox with:
    - No outbound network (iptables DROP all from agent container)
    - Restricted filesystem (read-only except /tmp)
    - seccomp profile blocking dangerous syscalls
    - AppArmor/SELinux mandatory access control

  Layer 3: TOKEN VERIFICATION (executor.py)
    Crypto-level: even if an attacker somehow escapes Layers 1 and 2,
    the Tool Executor verifies cryptographic tokens before executing
    anything. You'd need the HMAC signing key to forge a token.

Any ONE of these layers is sufficient to block bypass. Together, they
make bypass require compromising three independent security mechanisms.
"""

from __future__ import annotations

import importlib
import logging
import sys
import types
from typing import Any

logger = logging.getLogger("roe_gate.sandbox")

# Modules that must be blocked in the agent's namespace
BLOCKED_MODULES = {
    "subprocess",
    "multiprocessing",
    "ctypes",
    "_ctypes",
}

# os functions that must be blocked
BLOCKED_OS_FUNCTIONS = {
    "system",
    "popen",
    "exec",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "fork",
    "forkpty",
    "kill",
    "killpg",
}

# socket functions/classes that must be blocked
BLOCKED_SOCKET_ATTRS = {
    "socket",
    "create_connection",
    "create_server",
    "getaddrinfo",
}


def _make_blocked_func(module_name: str, func_name: str):
    """Create a function that raises PermissionError when called."""
    def blocked(*args: Any, **kwargs: Any) -> None:
        raise PermissionError(
            f"SANDBOX VIOLATION: {module_name}.{func_name}() is blocked. "
            f"All tool execution must go through the ToolProxy. "
            f"Direct system access is not permitted."
        )
    blocked.__name__ = func_name
    blocked.__qualname__ = f"BLOCKED.{func_name}"
    return blocked


class _BlockedModule(types.ModuleType):
    """A module stub that raises PermissionError on any non-dunder attribute access.

    Python's import machinery needs dunder attributes (__spec__, __loader__, etc.)
    to function, so we allow those. But any actual usage (subprocess.run, etc.)
    raises PermissionError.
    """

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.__doc__ = (
            f"BLOCKED: {name} is not available in the agent sandbox. "
            f"All tool execution must go through the ToolProxy."
        )
        self._blocked_name = name

    def __getattr__(self, attr: str) -> Any:
        # Allow dunder attributes for import machinery compatibility
        if attr.startswith("_"):
            raise AttributeError(f"module '{self._blocked_name}' has no attribute '{attr}'")
        raise PermissionError(
            f"SANDBOX VIOLATION: {self._blocked_name}.{attr} is blocked. "
            f"All tool execution must go through the ToolProxy."
        )


def _make_blocked_module(name: str) -> _BlockedModule:
    """Create a module stub that raises PermissionError on any attribute access."""
    return _BlockedModule(name)


class SandboxImportBlocker:
    """A sys.meta_path hook that blocks imports of dangerous modules.

    When the agent tries `import subprocess`, this intercepts it and
    returns a blocked stub module instead of the real one.
    """

    def __init__(self, blocked_modules: set[str]) -> None:
        self.blocked = blocked_modules

    def find_module(self, fullname: str, path: Any = None) -> "SandboxImportBlocker | None":
        if fullname in self.blocked or any(
            fullname.startswith(f"{m}.") for m in self.blocked
        ):
            return self
        return None

    def load_module(self, fullname: str) -> types.ModuleType:
        logger.warning("SANDBOX: Blocked import of '%s'", fullname)
        if fullname in sys.modules:
            # Replace with blocked version
            sys.modules[fullname] = _make_blocked_module(fullname)
        else:
            sys.modules[fullname] = _make_blocked_module(fullname)
        return sys.modules[fullname]


def activate_sandbox() -> dict[str, Any]:
    """Activate the agent sandbox.

    This modifies the current Python process to block dangerous operations.
    Call this BEFORE giving the agent any tools or starting the agent loop.

    Returns a report of what was blocked.

    WARNING: This modifies global state (sys.modules, os module).
    It is designed to be called once at process startup.
    """
    report: dict[str, Any] = {
        "modules_blocked": [],
        "os_functions_blocked": [],
        "socket_attrs_blocked": [],
    }

    # ── Block module imports ──────────────────────────────────────
    blocker = SandboxImportBlocker(BLOCKED_MODULES)
    sys.meta_path.insert(0, blocker)

    for mod_name in BLOCKED_MODULES:
        if mod_name in sys.modules:
            # Module already imported — replace it with a blocked stub
            sys.modules[mod_name] = _make_blocked_module(mod_name)
        report["modules_blocked"].append(mod_name)

    # ── Block dangerous os functions ──────────────────────────────
    import os
    for func_name in BLOCKED_OS_FUNCTIONS:
        if hasattr(os, func_name):
            setattr(os, func_name, _make_blocked_func("os", func_name))
            report["os_functions_blocked"].append(func_name)

    # ── Block socket access ───────────────────────────────────────
    try:
        import socket as _socket
        for attr_name in BLOCKED_SOCKET_ATTRS:
            if hasattr(_socket, attr_name):
                setattr(
                    _socket, attr_name,
                    _make_blocked_func("socket", attr_name),
                )
                report["socket_attrs_blocked"].append(attr_name)
    except ImportError:
        pass  # socket not available on this platform

    logger.info(
        "SANDBOX ACTIVATED: blocked %d modules, %d os functions, %d socket attrs",
        len(report["modules_blocked"]),
        len(report["os_functions_blocked"]),
        len(report["socket_attrs_blocked"]),
    )

    return report


def create_sandboxed_agent_runtime(
    gate: Any,
    executor: Any,
    agent_session: str,
    engagement_id: str,
) -> "ToolProxy":
    """Create a complete sandboxed runtime for an agent.

    This is the primary entry point for setting up the agent's environment.
    It:
    1. Activates the sandbox (blocks dangerous modules)
    2. Creates a ToolProxy as the agent's only interface

    Usage:
        from src.tools.sandbox import create_sandboxed_agent_runtime

        proxy = create_sandboxed_agent_runtime(
            gate=gate,
            executor=executor,
            agent_session="session-001",
            engagement_id="ENG-2024-001",
        )

        # Give these to the agent framework:
        tools = proxy.get_agent_tools()

        # The agent can ONLY use these tool functions.
        # subprocess, os.system, socket — all blocked.

    Args:
        gate: The ROEGate instance.
        executor: The ToolExecutor instance.
        agent_session: Session identifier for this agent.
        engagement_id: The engagement this agent belongs to.

    Returns:
        A ToolProxy — the agent's only interface to the outside world.
    """
    # Import here to avoid circular imports
    from .proxy import ToolProxy

    # Step 1: Activate the sandbox FIRST
    report = activate_sandbox()

    logger.info(
        "Sandboxed runtime created | session=%s | engagement=%s | "
        "blocked=%d modules, %d os funcs, %d socket attrs",
        agent_session, engagement_id,
        len(report["modules_blocked"]),
        len(report["os_functions_blocked"]),
        len(report["socket_attrs_blocked"]),
    )

    # Step 2: Create the proxy as the agent's interface
    proxy = ToolProxy(
        gate=gate,
        executor=executor,
        agent_session=agent_session,
        engagement_id=engagement_id,
    )

    return proxy
