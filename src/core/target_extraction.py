"""
Target Extraction -- Detect network targets in arbitrary command strings.

This module scans command strings for network targets (IP addresses, URLs,
CIDR notation, /dev/tcp redirections, hostnames) AND embedded network tool
invocations to catch commands that could affect network hosts, regardless
of what tool is being used.

Used by:
  - .claude/hooks/bash_gate_hook.py (inlined copy for standalone operation)
  - examples/claude_code_pentest_agent.py (imported)
"""

from __future__ import annotations

import os
import re


# Pre-compiled patterns for performance
_IPV4_RE = re.compile(
    r"(?<![.\w/])"  # not preceded by dot, word char, or slash (avoid file paths, version strings)
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"(?![.\w])"  # not followed by dot or word char (avoid version strings like 3.10.0.1)
)

_IPV6_RE = re.compile(
    r"(?<![:\w])"
    r"("
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"  # full form
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"  # trailing ::
    r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"  # leading ::
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"  # :: in middle
    r"|::1"  # loopback
    r")"
    r"(?![:\w])"
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

# Well-known hostnames that are always network targets
_NETWORK_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
}

# Hostname-like patterns: word.tld or word.word.tld
_HOSTNAME_RE = re.compile(
    r"(?<![.\w/])"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"\.(?:com|net|org|io|dev|app|gov|edu|mil|co|us|uk|de|fr|jp|cn|ru|br|in|au|ca|it|xyz|info|biz|me|tv|cc|ly))"
    r"(?![.\w])",
    re.IGNORECASE,
)

# Network tools that should be caught even when embedded inside interpreter
# commands like python3 -c "subprocess.run(['ping', ...])"
NETWORK_TOOL_NAMES = {
    "nmap", "masscan", "rustscan",
    "curl", "wget", "httpx",
    "sqlmap", "nikto", "dirb", "gobuster", "ffuf",
    "hydra", "medusa",
    "psql", "mysql", "mongo", "mongosh", "redis-cli",
    "ssh", "scp", "ftp", "smbclient", "telnet",
    "metasploit", "msfconsole", "msfvenom",
    "nuclei", "subfinder", "amass", "dig", "nslookup",
    "whois", "theHarvester",
    "nc", "netcat", "socat",
    "ping", "ping6", "fping",
    "traceroute", "traceroute6", "mtr",
    "hping3", "arping", "nping",
    "tcpdump", "tshark",
}

# Gate's own address — never flag connections to the gate itself
_GATE_PORT = os.environ.get("ROE_GATE_PORT", "19990")


def _is_valid_ipv4(ip: str) -> bool:
    """Check if string is a valid IPv4 address (all octets 0-255)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def extract_network_targets(command: str) -> list[str]:
    """Extract potential network targets from a command string.

    Scans for:
      - IPv4 addresses (validated: octets 0-255)
      - IPv6 addresses (common forms)
      - URLs (http://, https://, ftp://)
      - CIDR notation (10.0.0.0/24)
      - Bash /dev/tcp and /dev/udp redirections
      - Well-known hostnames (localhost, etc.)
      - Dotted domain names (example.com, api.acme.com)

    Filters out:
      - The gate's own address (localhost on ROE_GATE_PORT)
      - Invalid IPv4 (octets > 255)

    Args:
        command: The full shell command string.

    Returns:
        List of unique target strings found. Empty list if no targets detected.
    """
    targets: list[str] = []
    seen: set[str] = set()

    def _add(target: str) -> None:
        if target not in seen:
            seen.add(target)
            targets.append(target)

    # --- IPv4 addresses ---
    for match in _IPV4_RE.finditer(command):
        ip = match.group(1)
        if _is_valid_ipv4(ip):
            _add(ip)

    # --- CIDR notation (before URL to avoid double-matching) ---
    for match in _CIDR_RE.finditer(command):
        _add(match.group(1))

    # --- URLs ---
    for match in _URL_RE.finditer(command):
        _add(match.group(1))

    # --- IPv6 addresses ---
    for match in _IPV6_RE.finditer(command):
        _add(match.group(1))

    # --- Bash /dev/tcp and /dev/udp ---
    for match in _DEV_TCP_UDP_RE.finditer(command):
        host = match.group(1)
        port = match.group(2)
        _add(f"/dev/tcp/{host}/{port}" if "tcp" in match.group(0) else f"/dev/udp/{host}/{port}")
        if _is_valid_ipv4(host):
            _add(host)

    # --- Well-known hostnames (localhost, etc.) ---
    cmd_lower = command.lower()
    for hostname in _NETWORK_HOSTNAMES:
        if hostname in cmd_lower:
            _add(hostname)

    # --- Dotted domain names (example.com, api.acme.com) ---
    for match in _HOSTNAME_RE.finditer(command):
        _add(match.group(1))

    return targets


def find_embedded_network_tools(command: str) -> list[str]:
    """Find network tool names embedded anywhere in a command string.

    Catches bypass attempts like:
      python3 -c "subprocess.run(['ping', '-c', '4', 'localhost'])"
      bash -c "nmap 10.0.0.5"
      perl -e "system('curl http://target.com')"

    Only matches whole-word occurrences to avoid false positives
    (e.g., "mapping" should NOT match "ping").

    Args:
        command: The full shell command string.

    Returns:
        List of network tool names found in the command.
    """
    found: list[str] = []
    seen: set[str] = set()
    for tool in NETWORK_TOOL_NAMES:
        if tool in seen:
            continue
        # Use word boundary matching — tool must appear as a standalone word
        # Allow quotes, brackets, parens around it (common in ['ping'] patterns)
        pattern = r"""(?<![a-zA-Z0-9_-])""" + re.escape(tool) + r"""(?![a-zA-Z0-9_-])"""
        if re.search(pattern, command):
            seen.add(tool)
            found.append(tool)
    return found
