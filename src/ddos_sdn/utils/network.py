"""Cross-platform network helpers for the traffic generators.

Replaces the Linux-only `popen('ifconfig | awk ...')` shell-out that lived
in benign_traffic.py before Phase 1. psutil works identically on Linux,
macOS, and Windows.
"""

from __future__ import annotations

import socket

import psutil

_LOOPBACK_PREFIX = "127."


def resolve_interface(preferred: str | None = None) -> str | None:
    """Return a sendable interface name, or None to let scapy decide.

    Preference order:
        1. The explicit ``preferred`` argument if it names an existing interface
           on this host. (Even loopback is honored here — if the caller asked
           for it, they get it.)
        2. The first interface that has at least one non-loopback IPv4 address.
        3. ``None`` — scapy will fall back to ``conf.iface``.
    """
    interfaces = psutil.net_if_addrs()

    if preferred is not None and preferred in interfaces:
        return preferred

    for name, addrs in interfaces.items():
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            if addr.address and not addr.address.startswith(_LOOPBACK_PREFIX):
                return name

    return None
