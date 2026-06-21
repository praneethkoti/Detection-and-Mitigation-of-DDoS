"""Unit tests for the Phase 3 §3.A `ofp_flow_mod` drop rule.

The real POX controller path requires Linux + a running POX runtime; this
test file stubs `pox.*` modules in `sys.modules` so the controller module
imports cleanly anywhere pytest runs. The stubs capture every message that
would be dispatched to `core.openflow.sendToDPID`, plus the constructor
arguments of `ofp_flow_mod` and `ofp_match`, so we can assert exactly what
the controller would send to a real OVS switch.

Three behavioral assertions (Phase 3 §3.J):

  1. test_check_ddos_installs_flow_mod_above_threshold —
     synthetic port_stats with count=60 triggers exactly one
     ofp_flow_mod(command=OFPFC_ADD, in_port=3, nw_src=10.0.0.1,
                  actions=[], hard_timeout=30,
                  priority=OFP_DEFAULT_PRIORITY+1) to dpid=1.

  2. test_check_ddos_below_threshold_does_nothing —
     count=10 (below threshold=50) dispatches zero messages AND leaves
     port_stats entries untouched (count stays at 10) — locks the
     "non-installed entries keep accumulating" semantic.

  3. test_check_ddos_retains_nw_src_after_install —
     After install, port_stats[(1,3)]["count"] == 0 (reset) and
     port_stats[(1,3)]["nw_src"] == "10.0.0.1" (retained). This is the
     recovery-semantics regression guard: a returning attacker after
     hard_timeout expiry re-trips one window later, not threshold packets
     later.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

# ---------- POX stubs ------------------------------------------------
# Install before importing the controller module. Each stub captures the
# constructor kwargs / call args that pox_controller.py would invoke
# against a real POX runtime.

_CAPTURED_MESSAGES: list[dict[str, Any]] = []  # messages sent via sendToDPID


class _OfpMatchStub:
    """Stub for pox.openflow.libopenflow_01.ofp_match."""

    def __init__(self, **kwargs):
        self.in_port = kwargs.get("in_port")
        self.nw_src = kwargs.get("nw_src")
        self.kwargs = dict(kwargs)


class _OfpFlowModStub:
    """Stub for pox.openflow.libopenflow_01.ofp_flow_mod."""

    def __init__(self, **kwargs):
        self.command = kwargs.get("command")
        self.match = kwargs.get("match")
        self.actions = kwargs.get("actions")
        self.hard_timeout = kwargs.get("hard_timeout")
        self.priority = kwargs.get("priority")
        self.kwargs = dict(kwargs)


class _OfpPacketOutStub:
    def __init__(self, **kwargs):
        self.kwargs = dict(kwargs)


class _ActionOutputStub:
    def __init__(self, **kwargs):
        self.kwargs = dict(kwargs)


def _install_pox_stubs() -> None:
    if "pox" in sys.modules:
        return

    # pox + pox.core
    pox = types.ModuleType("pox")
    pox_core = types.ModuleType("pox.core")

    class _CoreStub:
        class _OpenflowStub:
            @staticmethod
            def sendToDPID(dpid, msg):
                _CAPTURED_MESSAGES.append({"dpid": dpid, "msg": msg})

        openflow = _OpenflowStub()

        @staticmethod
        def getLogger(*_args, **_kw):
            import logging

            return logging.getLogger("pox.stub")

        @staticmethod
        def listen_to_dependencies(_self):
            pass

    pox_core.core = _CoreStub()
    sys.modules["pox"] = pox
    sys.modules["pox.core"] = pox_core

    # pox.lib + pox.lib.packet.*
    for name in (
        "pox.lib",
        "pox.lib.packet",
        "pox.lib.packet.ethernet",
        "pox.lib.packet.ipv4",
        "pox.lib.packet.arp",
        "pox.lib.addresses",
        "pox.lib.revent",
        "pox.lib.recoco",
        "pox.openflow",
        "pox.openflow.libopenflow_01",
    ):
        sys.modules[name] = types.ModuleType(name)

    sys.modules["pox.lib.packet.ethernet"].ethernet = type("ethernet", (), {})
    sys.modules["pox.lib.packet.ethernet"].ETHER_BROADCAST = "ff:ff:ff:ff:ff:ff"
    sys.modules["pox.lib.packet.ipv4"].ipv4 = type("ipv4", (), {})
    sys.modules["pox.lib.packet.arp"].arp = type("arp", (), {})

    addresses = sys.modules["pox.lib.addresses"]
    addresses.IPAddr = lambda s: f"IPAddr({s})"
    addresses.EthAddr = lambda s: f"EthAddr({s})"

    revent = sys.modules["pox.lib.revent"]
    revent.EventMixin = type("EventMixin", (), {})

    recoco = sys.modules["pox.lib.recoco"]

    class _TimerStub:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    recoco.Timer = _TimerStub

    of = sys.modules["pox.openflow.libopenflow_01"]
    of.OFPFC_ADD = "OFPFC_ADD"
    of.OFP_DEFAULT_PRIORITY = 32768
    of.ofp_match = _OfpMatchStub
    of.ofp_flow_mod = _OfpFlowModStub
    of.ofp_packet_out = _OfpPacketOutStub
    of.ofp_action_output = _ActionOutputStub


_install_pox_stubs()

# ---------- Import the module under test (after stubs) ----------------
from ddos_sdn.detector import pox_controller as ctrl  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_state():
    """Reset module-level state and captured-message buffer for each test."""
    ctrl.port_stats.clear()
    _CAPTURED_MESSAGES.clear()
    yield
    ctrl.port_stats.clear()
    _CAPTURED_MESSAGES.clear()


def test_check_ddos_installs_flow_mod_above_threshold() -> None:
    ctrl.port_stats[(1, 3)] = {"count": 60, "nw_src": "10.0.0.1"}
    ctrl.check_ddos()
    assert len(_CAPTURED_MESSAGES) == 1, _CAPTURED_MESSAGES
    captured = _CAPTURED_MESSAGES[0]
    assert captured["dpid"] == 1
    msg = captured["msg"]
    assert isinstance(msg, _OfpFlowModStub)
    assert msg.command == "OFPFC_ADD"
    assert msg.match.in_port == 3
    assert msg.match.nw_src == "IPAddr(10.0.0.1)"  # stub IPAddr wraps in this prefix
    assert msg.actions == []
    assert msg.hard_timeout == 30
    assert msg.priority == 32768 + 1  # OFP_DEFAULT_PRIORITY + 1


def test_check_ddos_below_threshold_does_nothing() -> None:
    ctrl.port_stats[(1, 3)] = {"count": 10, "nw_src": "10.0.0.1"}
    ctrl.check_ddos()
    # No flow_mod was sent.
    assert _CAPTURED_MESSAGES == []
    # Critically: the entry is UNTOUCHED. Pre-Phase-3 behavior would have
    # blanket-wiped port_stats; the new per-key reset only resets entries
    # that triggered an install.
    assert ctrl.port_stats[(1, 3)] == {"count": 10, "nw_src": "10.0.0.1"}


def test_check_ddos_retains_nw_src_after_install() -> None:
    """Recovery semantics: after install, count resets but nw_src is kept."""
    ctrl.port_stats[(1, 3)] = {"count": 60, "nw_src": "10.0.0.1"}
    ctrl.check_ddos()
    entry = ctrl.port_stats[(1, 3)]
    assert entry["count"] == 0, f"count should reset to 0, got {entry['count']}"
    assert (
        entry["nw_src"] == "10.0.0.1"
    ), f"nw_src should be retained for fast re-install after hard_timeout, got {entry['nw_src']!r}"


def test_pox_controller_falls_back_to_standalone_when_coordinator_disabled() -> None:
    """Phase 4b backward-compat guard: coordinator.enabled=false means the
    controller never opens a TCP connection to a coordinator and never
    constructs a WorkerClient. The Phase 3 standalone code path is
    preserved bit-for-bit.

    The default config (built-in DEFAULTS) has coordinator.enabled=false,
    so the already-imported `ctrl` module loaded under that regime. We
    assert that the module-level handle was never populated and that the
    standalone install path still works (single ofp_flow_mod via
    check_ddos() on the synthetic port_stats entry).
    """
    # The standalone path must have left the coordinator handle uninitialized.
    assert ctrl._coordinator_client is None, (
        "coordinator.enabled=false must leave _coordinator_client=None — "
        "no East-West socket should be opened in standalone mode"
    )
    assert ctrl._coordinator_enabled is False, (
        "DEFAULTS must keep coordinator.enabled=false so existing single-controller "
        "deployments and demo.py keep Phase 3 behavior verbatim"
    )

    # And the Phase 3 install path still triggers a real flow_mod without
    # any coordinator involvement.
    ctrl.port_stats[(1, 3)] = {"count": 60, "nw_src": "10.0.0.1"}
    ctrl.check_ddos()
    assert (
        len(_CAPTURED_MESSAGES) == 1
    ), f"standalone path must install exactly one drop rule, got {_CAPTURED_MESSAGES}"
