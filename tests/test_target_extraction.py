"""Tests for target extraction from command strings.

Validates that the four-tier command gating system correctly identifies
network targets in arbitrary commands, catching bypass attempts that the
old tool-name-only blocklist would miss.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.core.target_extraction import extract_network_targets, find_embedded_network_tools


# ---------------------------------------------------------------------------
# IPv4 Detection
# ---------------------------------------------------------------------------


class TestIPv4Detection:
    """IPv4 addresses should be extracted from command strings."""

    def test_simple_ipv4(self):
        targets = extract_network_targets("nmap 10.0.0.5")
        assert "10.0.0.5" in targets

    def test_multiple_ipv4(self):
        targets = extract_network_targets("nmap 10.0.0.5 10.0.0.6 10.0.0.7")
        assert "10.0.0.5" in targets
        assert "10.0.0.6" in targets
        assert "10.0.0.7" in targets

    def test_ipv4_in_python_code(self):
        cmd = """python3 -c "import socket; s = socket.socket(); s.connect(('10.0.0.5', 80))" """
        targets = extract_network_targets(cmd)
        assert "10.0.0.5" in targets

    def test_ipv4_in_perl_code(self):
        cmd = """perl -e "IO::Socket::INET->new(PeerAddr=>'10.0.0.5:80')" """
        targets = extract_network_targets(cmd)
        assert "10.0.0.5" in targets

    def test_ipv4_in_ruby_code(self):
        cmd = """ruby -e "TCPSocket.new('192.168.1.100', 443)" """
        targets = extract_network_targets(cmd)
        assert "192.168.1.100" in targets

    def test_ipv4_with_port_colon(self):
        targets = extract_network_targets("connect 10.0.0.5:8080")
        assert "10.0.0.5" in targets

    def test_private_ranges(self):
        targets = extract_network_targets("scan 172.16.0.1 192.168.0.1")
        assert "172.16.0.1" in targets
        assert "192.168.0.1" in targets

    def test_public_ip(self):
        targets = extract_network_targets("curl 8.8.8.8")
        assert "8.8.8.8" in targets

    def test_boundary_octets(self):
        targets = extract_network_targets("scan 0.0.0.0 255.255.255.255")
        assert "0.0.0.0" in targets
        assert "255.255.255.255" in targets

    def test_ipv4_invalid_octets_filtered(self):
        """Octets > 255 should not be treated as valid IPs."""
        targets = extract_network_targets("connect 999.999.999.999")
        assert "999.999.999.999" not in targets

    def test_deduplication(self):
        """Same IP appearing twice should only appear once in results."""
        targets = extract_network_targets("ping 10.0.0.5 && ping 10.0.0.5")
        assert targets.count("10.0.0.5") == 1

    def test_ipv4_in_java_command(self):
        cmd = "java -jar scanner.jar --target 10.0.0.5 --port 80"
        targets = extract_network_targets(cmd)
        assert "10.0.0.5" in targets

    def test_ipv4_in_custom_binary(self):
        cmd = "/opt/custom_scanner 10.0.0.5"
        targets = extract_network_targets(cmd)
        assert "10.0.0.5" in targets


# ---------------------------------------------------------------------------
# IPv4 False Positive Filtering
# ---------------------------------------------------------------------------


class TestIPv4FalsePositives:
    """Version numbers, file paths, etc. should NOT be detected as IPs."""

    def test_three_octet_version_not_matched(self):
        """Version like 3.10.0 has only 3 parts — not an IP."""
        targets = extract_network_targets("python3.10.0 --version")
        # 3.10.0 only has 3 parts, regex requires 4 dotted groups
        assert not any("3.10" in t for t in targets)

    def test_no_targets_in_ls(self):
        targets = extract_network_targets("ls -la /tmp/mydir")
        assert targets == []

    def test_no_targets_in_grep(self):
        targets = extract_network_targets("grep -r 'pattern' src/")
        assert targets == []

    def test_no_targets_in_git(self):
        targets = extract_network_targets("git log --oneline -10")
        assert targets == []

    def test_no_targets_in_cat(self):
        targets = extract_network_targets("cat /etc/hosts")
        assert targets == []


# ---------------------------------------------------------------------------
# URL Detection
# ---------------------------------------------------------------------------


class TestURLDetection:
    """HTTP/HTTPS/FTP URLs should be detected."""

    def test_http_url(self):
        targets = extract_network_targets("wget http://example.com/file.zip")
        assert any("http://example.com" in t for t in targets)

    def test_https_url(self):
        targets = extract_network_targets("curl https://api.corp.local/v1/users")
        assert any("https://api.corp.local" in t for t in targets)

    def test_ftp_url(self):
        targets = extract_network_targets("wget ftp://files.example.com/data.tar")
        assert any("ftp://files.example.com" in t for t in targets)

    def test_url_with_port(self):
        targets = extract_network_targets("curl http://10.0.0.5:8080/api")
        assert any("http://10.0.0.5:8080" in t for t in targets)

    def test_url_in_python(self):
        cmd = """python3 -c "import urllib.request; urllib.request.urlopen('http://target.com')" """
        targets = extract_network_targets(cmd)
        assert any("http://target.com" in t for t in targets)

    def test_multiple_urls(self):
        cmd = "curl http://a.com && curl https://b.com"
        targets = extract_network_targets(cmd)
        urls = [t for t in targets if "://" in t]
        assert len(urls) >= 2


# ---------------------------------------------------------------------------
# CIDR Detection
# ---------------------------------------------------------------------------


class TestCIDRDetection:
    """CIDR notation should be detected."""

    def test_cidr_24(self):
        targets = extract_network_targets("nmap 10.0.0.0/24")
        assert "10.0.0.0/24" in targets

    def test_cidr_16(self):
        targets = extract_network_targets("scan 192.168.0.0/16")
        assert "192.168.0.0/16" in targets

    def test_cidr_32(self):
        targets = extract_network_targets("target 10.0.0.5/32")
        assert "10.0.0.5/32" in targets


# ---------------------------------------------------------------------------
# /dev/tcp and /dev/udp Detection
# ---------------------------------------------------------------------------


class TestDevTcpUdpDetection:
    """Bash /dev/tcp and /dev/udp redirections should be detected."""

    def test_dev_tcp_ip(self):
        cmd = 'bash -c "echo > /dev/tcp/10.0.0.5/80"'
        targets = extract_network_targets(cmd)
        assert any("/dev/tcp/10.0.0.5/80" in t for t in targets)

    def test_dev_udp_ip(self):
        cmd = 'bash -c "echo > /dev/udp/10.0.0.5/53"'
        targets = extract_network_targets(cmd)
        assert any("/dev/udp/10.0.0.5/53" in t for t in targets)

    def test_dev_tcp_hostname(self):
        cmd = 'bash -c "cat < /dev/tcp/target.com/443"'
        targets = extract_network_targets(cmd)
        assert any("/dev/tcp/target.com/443" in t for t in targets)

    def test_dev_tcp_also_extracts_ip(self):
        """When /dev/tcp has an IP host, that IP should also be in targets."""
        cmd = 'echo test > /dev/tcp/10.0.0.5/80'
        targets = extract_network_targets(cmd)
        assert "10.0.0.5" in targets


# ---------------------------------------------------------------------------
# IPv6 Detection
# ---------------------------------------------------------------------------


class TestIPv6Detection:
    """IPv6 addresses should be detected."""

    def test_ipv6_loopback(self):
        targets = extract_network_targets("ping6 ::1")
        assert "::1" in targets

    def test_ipv6_full_form(self):
        targets = extract_network_targets("connect 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" in targets


# ---------------------------------------------------------------------------
# Bypass Scenarios
# ---------------------------------------------------------------------------


class TestBypassScenarios:
    """Commands that previously bypassed the tool-name blocklist."""

    def test_python_socket_connect(self):
        cmd = """python3 -c "import socket; s = socket.socket(); s.connect(('10.0.0.5', 80))" """
        targets = extract_network_targets(cmd)
        assert "10.0.0.5" in targets

    def test_perl_network_code(self):
        cmd = """perl -e "use IO::Socket; IO::Socket::INET->new(PeerAddr=>'192.168.1.50:80')" """
        targets = extract_network_targets(cmd)
        assert "192.168.1.50" in targets

    def test_bash_dev_tcp_redirect(self):
        cmd = 'bash -c "echo > /dev/tcp/10.0.0.5/80"'
        targets = extract_network_targets(cmd)
        assert len(targets) > 0
        assert any("10.0.0.5" in t for t in targets)

    def test_custom_binary_with_target(self):
        cmd = "/usr/local/bin/custom_scanner --host 10.0.0.5 --port 443"
        targets = extract_network_targets(cmd)
        assert "10.0.0.5" in targets

    def test_netcat_piped(self):
        cmd = "echo hello | nc 10.0.0.5 80"
        targets = extract_network_targets(cmd)
        assert "10.0.0.5" in targets

    def test_python_urllib(self):
        cmd = """python3 -c "import urllib.request; urllib.request.urlopen('http://10.0.0.5:8080/api')" """
        targets = extract_network_targets(cmd)
        assert any("10.0.0.5" in t for t in targets)

    def test_socat_connection(self):
        cmd = "socat - TCP:10.0.0.5:80"
        targets = extract_network_targets(cmd)
        assert "10.0.0.5" in targets

    def test_ruby_tcp_socket(self):
        cmd = """ruby -e "require 'socket'; TCPSocket.new('10.0.0.5', 80)" """
        targets = extract_network_targets(cmd)
        assert "10.0.0.5" in targets


# ---------------------------------------------------------------------------
# Safe Commands (should produce no targets)
# ---------------------------------------------------------------------------


class TestSafeCommands:
    """Commands that do NOT target the network should produce no targets."""

    def test_ls(self):
        assert extract_network_targets("ls -la") == []

    def test_cat_file(self):
        assert extract_network_targets("cat /etc/passwd") == []

    def test_grep_pattern(self):
        assert extract_network_targets("grep -r 'error' src/") == []

    def test_echo_text(self):
        """Echo doesn't affect the network, but we detect IPs in strings.
        The SAFE_COMMANDS allowlist in the hook handles this — echo is safe
        regardless of arguments. Here we test that extract_network_targets
        DOES find the IP (the hook skips extraction for safe commands)."""
        targets = extract_network_targets("echo 10.0.0.5")
        assert "10.0.0.5" in targets  # Function finds it; hook allows echo anyway

    def test_mkdir(self):
        assert extract_network_targets("mkdir -p /tmp/output") == []

    def test_python_no_targets(self):
        assert extract_network_targets("python3 --version") == []

    def test_git_local(self):
        assert extract_network_targets("git log --oneline -10") == []

    def test_make_build(self):
        assert extract_network_targets("make build") == []

    def test_tar_extract(self):
        assert extract_network_targets("tar xzf archive.tar.gz") == []


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_command(self):
        assert extract_network_targets("") == []

    def test_whitespace_only(self):
        assert extract_network_targets("   ") == []

    def test_ip_at_end_of_command(self):
        targets = extract_network_targets("scan 10.0.0.5")
        assert "10.0.0.5" in targets

    def test_ip_at_start_of_command(self):
        targets = extract_network_targets("10.0.0.5 something")
        assert "10.0.0.5" in targets

    def test_ip_in_quotes(self):
        targets = extract_network_targets("""connect '10.0.0.5' """)
        assert "10.0.0.5" in targets

    def test_ip_in_double_quotes(self):
        targets = extract_network_targets("""connect "10.0.0.5" """)
        assert "10.0.0.5" in targets

    def test_multiple_target_types(self):
        """Command with IP, URL, and CIDR all at once."""
        cmd = "scan 10.0.0.5 http://example.com 192.168.0.0/16"
        targets = extract_network_targets(cmd)
        assert "10.0.0.5" in targets
        assert any("http://example.com" in t for t in targets)
        assert "192.168.0.0/16" in targets

    def test_localhost_ip_detected(self):
        """localhost IPs should be detected — the gate decides scope, not us."""
        targets = extract_network_targets("nmap 127.0.0.1")
        assert "127.0.0.1" in targets


# ---------------------------------------------------------------------------
# Hostname Detection
# ---------------------------------------------------------------------------


class TestHostnameDetection:
    """Well-known hostnames and domain names should be detected."""

    def test_localhost_string(self):
        targets = extract_network_targets("ping localhost")
        assert "localhost" in targets

    def test_localhost_in_python(self):
        cmd = """python3 -c "subprocess.run(['ping', '-c', '4', 'localhost'])" """
        targets = extract_network_targets(cmd)
        assert "localhost" in targets

    def test_localhost_in_subprocess(self):
        cmd = """python3 -c "import subprocess; subprocess.run(['ping', '-c', '4', 'localhost'])" """
        targets = extract_network_targets(cmd)
        assert "localhost" in targets

    def test_localhost_localdomain(self):
        targets = extract_network_targets("ping localhost.localdomain")
        assert "localhost.localdomain" in targets

    def test_domain_name_com(self):
        targets = extract_network_targets("connect target.com")
        assert "target.com" in targets

    def test_domain_name_subdomain(self):
        targets = extract_network_targets("scan api.corp.local")
        assert "api.corp.local" in targets

    def test_domain_name_org(self):
        targets = extract_network_targets("wget example.org/file")
        assert "example.org" in targets

    def test_domain_not_file_extension(self):
        """File extensions like .py, .txt should NOT match."""
        targets = extract_network_targets("python3 script.py")
        assert not any(".py" in t for t in targets)

    def test_localhost_case_insensitive(self):
        targets = extract_network_targets("ping LOCALHOST")
        assert "localhost" in targets


# ---------------------------------------------------------------------------
# Embedded Network Tool Detection
# ---------------------------------------------------------------------------


class TestEmbeddedToolDetection:
    """Network tools wrapped in interpreter commands should be detected."""

    def test_ping_in_subprocess_run(self):
        cmd = """python3 -c "subprocess.run(['ping', '-c', '4', 'localhost'])" """
        found = find_embedded_network_tools(cmd)
        assert "ping" in found

    def test_nmap_in_os_system(self):
        cmd = """python3 -c "import os; os.system('nmap 10.0.0.5')" """
        found = find_embedded_network_tools(cmd)
        assert "nmap" in found

    def test_curl_in_bash_c(self):
        cmd = """bash -c "curl http://target.com" """
        found = find_embedded_network_tools(cmd)
        assert "curl" in found

    def test_ssh_in_perl(self):
        cmd = """perl -e "system('ssh user@10.0.0.5')" """
        found = find_embedded_network_tools(cmd)
        assert "ssh" in found

    def test_no_false_positive_mapping(self):
        """'mapping' should NOT match 'ping'."""
        found = find_embedded_network_tools("process the mapping data")
        assert "ping" not in found

    def test_no_false_positive_tracker(self):
        """'tracker' should NOT match 'traceroute'."""
        found = find_embedded_network_tools("update the bug tracker")
        assert "traceroute" not in found

    def test_no_false_positive_curling(self):
        """'curling' should NOT match 'curl'."""
        found = find_embedded_network_tools("the curling match was great")
        assert "curl" not in found

    def test_ping_in_quotes(self):
        """Tool name inside quotes should be detected."""
        found = find_embedded_network_tools("""run(['ping'])""")
        assert "ping" in found

    def test_multiple_embedded_tools(self):
        cmd = """bash -c "nmap 10.0.0.5 && curl http://10.0.0.5" """
        found = find_embedded_network_tools(cmd)
        assert "nmap" in found
        assert "curl" in found

    def test_no_tools_in_safe_command(self):
        """Plain safe commands should not trigger."""
        found = find_embedded_network_tools("ls -la /tmp")
        assert found == []

    def test_netcat_in_python(self):
        cmd = """python3 -c "os.system('nc 10.0.0.5 80')" """
        found = find_embedded_network_tools(cmd)
        assert "nc" in found

    def test_tcpdump_in_script(self):
        cmd = """bash -c "tcpdump -i eth0 -w capture.pcap" """
        found = find_embedded_network_tools(cmd)
        assert "tcpdump" in found


# ---------------------------------------------------------------------------
# Combined Bypass Scenarios (the actual attack that was demonstrated)
# ---------------------------------------------------------------------------


class TestDemonstratedBypasses:
    """Real bypass scenarios that were demonstrated in testing."""

    def test_subprocess_ping_localhost(self):
        """THE bypass that was demonstrated: subprocess.run(['ping', 'localhost']).
        Both 'localhost' hostname AND 'ping' embedded tool should be caught."""
        cmd = """python3 -c "import subprocess; subprocess.run(['ping', '-c', '4', 'localhost'])" """
        targets = extract_network_targets(cmd)
        assert "localhost" in targets
        embedded = find_embedded_network_tools(cmd)
        assert "ping" in embedded

    def test_os_system_nmap_localhost(self):
        cmd = """python3 -c "import os; os.system('nmap localhost')" """
        targets = extract_network_targets(cmd)
        assert "localhost" in targets
        embedded = find_embedded_network_tools(cmd)
        assert "nmap" in embedded

    def test_subprocess_curl_domain(self):
        cmd = """python3 -c "subprocess.run(['curl', 'http://example.com'])" """
        targets = extract_network_targets(cmd)
        assert any("http://example.com" in t for t in targets)
        embedded = find_embedded_network_tools(cmd)
        assert "curl" in embedded
