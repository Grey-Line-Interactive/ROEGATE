#!/usr/bin/env python3
"""
ROE Gate -- Bash PreToolUse Hook for Claude Code

Three-tier command gating that catches ANY command targeting network hosts,
not just known tool names.

  Tier 0: SAFE_COMMANDS -- commands that cannot affect the network (ls, cat, grep, etc.)
          → allowed immediately
  Tier 1: KNOWN_NETWORK_TOOLS -- known pentest/network tools (nmap, curl, ssh, etc.)
          → denied with specific MCP tool suggestion
  Tier 2: TARGET EXTRACTION -- scans command for IPs, URLs, CIDRs, /dev/tcp
          → denied if network targets found, allowed otherwise

Hook protocol:
  - Receives JSON on stdin: {"tool_name": "Bash", "tool_input": {"command": "..."}, ...}
  - To DENY: print JSON to stdout with permissionDecision: "deny"
  - To ALLOW: exit 0 with no output
"""

import json
import os
import re
import sys


# ---------------------------------------------------------------------------
# Tier 0: Commands that CANNOT affect the network regardless of arguments
# ---------------------------------------------------------------------------

SAFE_COMMANDS = {
    # File listing / info
    "ls", "dir", "stat", "file", "readlink", "realpath", "basename", "dirname",
    # File reading
    "cat", "head", "tail", "less", "more", "tac", "rev",
    # File manipulation
    "cp", "mv", "rm", "mkdir", "rmdir", "touch", "ln", "install",
    "chmod", "chown", "chgrp",
    # Text processing
    "grep", "egrep", "fgrep", "rg", "ag",
    "sed", "awk", "gawk", "mawk",
    "sort", "uniq", "cut", "tr", "paste", "join", "comm",
    "wc", "nl", "fold", "fmt", "column",
    "tee", "xargs",
    # Output
    "echo", "printf", "yes", "true", "false",
    # Shell builtins
    "cd", "pwd", "pushd", "popd", "dirs",
    "export", "set", "unset", "env", "printenv",
    "alias", "unalias", "type", "which", "where", "command",
    "test", "[",
    "read", "source",
    # Archives / compression
    "tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "bunzip2", "xz",
    "zcat", "zgrep", "zless",
    # Hashing
    "md5sum", "sha1sum", "sha256sum", "sha512sum", "shasum", "md5",
    "cksum", "sum", "b2sum",
    # Date / time
    "date", "cal", "sleep",
    # System info (read-only, non-network)
    "uname", "whoami", "id", "groups", "users", "who", "w",
    "uptime", "arch", "nproc",
    "df", "du", "free",
    "ps", "top", "htop", "pgrep",
    # Find / locate
    "find", "locate", "tree",
    # Diff / patch
    "diff", "patch", "cmp",
    # Editors
    "vim", "vi", "nano", "emacs", "ed", "ex", "code",
    # JSON / data processing
    "jq", "yq", "xmllint",
    # Man / help
    "man", "info", "help", "whatis", "apropos",
    # Build tools (local-only)
    "make", "cmake", "ninja",
    "gcc", "g++", "cc", "clang", "clang++",
    "ld", "ar", "nm", "objdump", "strip", "strings",
    # Version control (local operations)
    "git",
}


# ---------------------------------------------------------------------------
# Tier 1: Known network / pentest tools → specific MCP tool redirect
# ---------------------------------------------------------------------------

KNOWN_NETWORK_TOOLS = {
    # Port scanners
    "nmap", "masscan", "rustscan",
    # HTTP tools
    "curl", "wget", "httpx",
    # Web scanners
    "sqlmap", "nikto", "dirb", "gobuster", "ffuf",
    # Credential tools
    "hydra", "medusa", "john", "hashcat",
    # Database clients
    "psql", "mysql", "mongo", "mongosh", "redis-cli",
    # Remote access
    "ssh", "scp", "ftp", "smbclient", "telnet",
    # Exploitation
    "metasploit", "msfconsole", "msfvenom",
    # Reconnaissance
    "nuclei", "subfinder", "amass", "dig", "nslookup",
    "whois", "theHarvester",
    # Network utilities
    "nc", "netcat", "socat",
    # ICMP / network probes
    "ping", "ping6", "fping",
    # Path tracers
    "traceroute", "traceroute6", "mtr",
    # Packet crafting / capture
    "hping3", "arping", "nping",
    "tcpdump", "tshark",
}

MCP_TOOL_MAP = {
    "nmap": "roe_nmap_scan",
    "masscan": "roe_nmap_scan",
    "rustscan": "roe_nmap_scan",
    "curl": "roe_http_request",
    "wget": "roe_http_request",
    "httpx": "roe_http_request",
    "dig": "roe_dns_lookup",
    "nslookup": "roe_dns_lookup",
    "whois": "roe_dns_lookup",
    "gobuster": "roe_directory_scan",
    "dirb": "roe_directory_scan",
    "ffuf": "roe_directory_scan",
    "sqlmap": "roe_sql_injection_test",
    "nikto": "roe_shell_command",
}


# ---------------------------------------------------------------------------
# Tier 2: Target extraction -- detect network targets in any command
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    r"(?<![.\w/])"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?![.\w])"
)

_URL_RE = re.compile(
    r"((?:https?|ftp)://[^\s'\",;)}\]]+)",
    re.IGNORECASE,
)

_CIDR_RE = re.compile(
    r"(?<![.\w/])"
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})"
    r"(?![.\w])"
)

_DEV_TCP_UDP_RE = re.compile(
    r"/dev/(?:tcp|udp)/([^\s/]+)/(\d+)"
)

_IPV6_RE = re.compile(
    r"(?<![:\w])"
    r"("
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|::1"
    r")"
    r"(?![:\w])"
)

_HOSTNAME_RE = re.compile(
    r"(?<![.\w/])"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.(?:com|net|org|io|dev|app|gov|edu|mil|co|us|uk|de|fr|jp|cn|ru|br|in|au|ca|it|xyz|info|biz|me|tv|cc|ly))"
    r"(?![.\w])",
    re.IGNORECASE,
)

_NETWORK_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


def _is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def extract_network_targets(command: str) -> list[str]:
    """Extract IPs, URLs, CIDRs, hostnames, /dev/tcp targets from command string."""
    targets: list[str] = []
    seen: set[str] = set()

    def _add(target: str) -> None:
        if target not in seen:
            seen.add(target)
            targets.append(target)

    for match in _IPV4_RE.finditer(command):
        ip = match.group(1)
        if _is_valid_ipv4(ip):
            _add(ip)

    for match in _CIDR_RE.finditer(command):
        _add(match.group(1))

    for match in _URL_RE.finditer(command):
        _add(match.group(1))

    for match in _IPV6_RE.finditer(command):
        _add(match.group(1))

    for match in _DEV_TCP_UDP_RE.finditer(command):
        host = match.group(1)
        port = match.group(2)
        label = f"/dev/tcp/{host}/{port}" if "tcp" in match.group(0) else f"/dev/udp/{host}/{port}"
        _add(label)
        if _is_valid_ipv4(host):
            _add(host)

    cmd_lower = command.lower()
    for hostname in _NETWORK_HOSTNAMES:
        if hostname in cmd_lower:
            _add(hostname)

    for match in _HOSTNAME_RE.finditer(command):
        _add(match.group(1))

    return targets


def find_embedded_network_tools(command: str) -> list[str]:
    """Find network tool names embedded anywhere in a command string.

    Catches: python3 -c "subprocess.run(['ping', ...])"
    """
    found = []
    seen = set()
    for tool in KNOWN_NETWORK_TOOLS:
        if tool in seen:
            continue
        pattern = r"(?<![a-zA-Z0-9_-])" + re.escape(tool) + r"(?![a-zA-Z0-9_-])"
        if re.search(pattern, command):
            seen.add(tool)
            found.append(tool)
    return found


# ---------------------------------------------------------------------------
# Main hook logic
# ---------------------------------------------------------------------------


def main() -> None:
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)  # Can't parse input, allow

    command = data.get("tool_input", {}).get("command", "")
    parts = command.strip().split()
    if not parts:
        sys.exit(0)

    # Strip common command wrappers: sudo, env, timeout, nice, nohup
    skip_prefixes = {"sudo", "env", "timeout", "nice", "nohup"}
    idx = 0
    while idx < len(parts) and parts[idx] in skip_prefixes:
        prev = parts[idx]
        idx += 1
        if prev == "timeout" and idx < len(parts) and not parts[idx].startswith("-"):
            idx += 1  # skip the duration argument

    if idx >= len(parts):
        sys.exit(0)

    tool = parts[idx]
    # Handle absolute paths like /usr/bin/nmap
    tool_basename = tool.rsplit("/", 1)[-1] if "/" in tool else tool

    # --- Tier 0: Safe command → allow immediately ---
    if tool_basename in SAFE_COMMANDS:
        sys.exit(0)

    # --- Tier 1: Known network tool → deny with specific MCP suggestion ---
    if tool_basename in KNOWN_NETWORK_TOOLS:
        suggested = MCP_TOOL_MAP.get(tool_basename, "roe_shell_command")
        json.dump({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"BLOCKED: Direct '{tool_basename}' via Bash is not permitted. "
                    f"Use the '{suggested}' MCP tool instead. "
                    f"All pentest tools must go through the ROE Gate."
                ),
            }
        }, sys.stdout)
        return

    # --- Tier 2: Scan command for network targets ---
    targets = extract_network_targets(command)
    if targets:
        target_list = ", ".join(targets[:5])
        if len(targets) > 5:
            target_list += f" (+{len(targets) - 5} more)"
        json.dump({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"BLOCKED: This command targets network host(s): {target_list}. "
                    f"All commands affecting network hosts must be evaluated through "
                    f"the ROE Gate. Use 'roe_shell_command' with target_host parameter, "
                    f"or use the appropriate MCP tool (roe_nmap_scan, roe_http_request, etc.)."
                ),
            }
        }, sys.stdout)
        return

    # --- Tier 3: Check for embedded network tool invocations ---
    # Catches: python3 -c "subprocess.run(['ping', '-c', '4', 'localhost'])"
    embedded = find_embedded_network_tools(command)
    if embedded:
        tool_list = ", ".join(embedded[:5])
        suggested = MCP_TOOL_MAP.get(embedded[0], "roe_shell_command")
        json.dump({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"BLOCKED: This command invokes network tool(s) '{tool_list}' "
                    f"via a wrapper (subprocess, system call, etc.). "
                    f"All network tool usage must go through the ROE Gate. "
                    f"Use '{suggested}' or 'roe_shell_command' instead."
                ),
            }
        }, sys.stdout)
        return

    # --- No targets or tools found → allow (local operation) ---
    sys.exit(0)


if __name__ == "__main__":
    main()
