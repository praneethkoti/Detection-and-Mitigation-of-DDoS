# Copyright 2012-2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time

import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.recoco import Timer
from pox.lib.revent import *

from ddos_sdn.config import load_config
from ddos_sdn.detector.entropy import EntropyAnalyzer

cfg = load_config()
entropy_instance = EntropyAnalyzer()

# Phase 3 §3.A: keyed by (dpid, port) tuple so per-key reset is possible.
# Each entry: {"count": int, "nw_src": str | None}. nw_src is captured from
# entropy_instance.top_src at the moment monitor_ddos first records an event
# on this (dpid, port) — it's the attacker IP the controller will install
# an ofp_flow_mod drop rule against.
port_stats = {}

log = core.getLogger()


def monitor_ddos(event):
    """Record one PACKET_IN event on the (dpid, port) it arrived on.

    Captures the attacker IP from the entropy detector's top_src field the
    first time we see this key. Caller responsibility (in handle_packet):
    only invoke when entropy_instance.is_attack() returns True.
    """
    global port_stats
    key = (event.connection.dpid, event.port)
    entry = port_stats.setdefault(key, {"count": 0, "nw_src": None})
    entry["count"] += 1
    if entry["nw_src"] is None and entropy_instance.top_src is not None:
        entry["nw_src"] = entropy_instance.top_src
    log.info(
        "monitor_ddos: dpid=%s port=%s count=%d nw_src=%s",
        key[0],
        key[1],
        entry["count"],
        entry["nw_src"],
    )


def check_ddos():
    """Install ofp_flow_mod drop rules for any (dpid, port) past threshold.

    Per Phase 3 §3.A, this REPLACES the prior empty ofp_packet_out stub
    with a real OpenFlow drop rule (actions=[], priority above default,
    hard_timeout configurable). Per-key reset retains nw_src so a returning
    attacker re-trips one window later, not port_count_threshold packets
    later. Non-installed entries are left untouched so accumulation is
    not blanket-wiped on every tick.
    """
    threshold = cfg["detector"]["port_count_threshold"]
    hard_timeout = cfg["controller"]["flow_mod_hard_timeout_seconds"]
    for (dpid, port), entry in port_stats.items():
        if entry["count"] >= threshold and entry["nw_src"] is not None:
            log.info(
                "INSTALL DROP RULE: dpid=%s port=%s nw_src=%s hard_timeout=%ds",
                dpid,
                port,
                entry["nw_src"],
                hard_timeout,
            )
            msg = of.ofp_flow_mod(
                command=of.OFPFC_ADD,
                match=of.ofp_match(in_port=port, nw_src=IPAddr(entry["nw_src"])),
                actions=[],  # empty action list == drop in OpenFlow 1.0
                hard_timeout=hard_timeout,
                priority=of.OFP_DEFAULT_PRIORITY + 1,  # outrank L3 forward rule
            )
            core.openflow.sendToDPID(dpid, msg)
            # Per-key reset: count back to 0, nw_src retained so the next
            # threshold crossing after hard_timeout expiry is instant.
            entry["count"] = 0


class L3Switch(EventMixin):
    def __init__(self, fake_gws=None, arp_for_unknowns=False):
        self.fake_gateways = set(fake_gws) if fake_gws else set()
        self.arp_for_unknowns = arp_for_unknowns
        self.arp_cache = {}
        self._check_timer = Timer(
            cfg["detector"]["timer_interval_seconds"], check_ddos, recurring=True
        )
        core.listen_to_dependencies(self)

    def handle_packet(self, event):
        dpid = event.connection.dpid
        in_port = event.port
        packet = event.parsed

        if not packet.parsed:
            log.warning("Ignoring unparsed packet")
            return

        if isinstance(packet.next, ipv4):
            entropy_instance.collect_statistics(packet.next.dstip, src_ip=packet.next.srcip)
            log.info(f"Entropy Value: {entropy_instance.entropy_value}")

            if entropy_instance.is_attack():
                monitor_ddos(event)

            if packet.next.dstip in self.arp_cache.get(dpid, {}):
                dst_port = self.arp_cache[dpid][packet.next.dstip].port
                if dst_port != in_port:
                    self.forward_packet(event, dst_port)

        elif isinstance(packet.next, arp):
            self.handle_arp(packet, event)

    def handle_arp(self, packet, event):
        a = packet.next
        log.info(f"ARP {a.protosrc} => {a.protodst}")
        cache = self.arp_cache.setdefault(event.connection.dpid, {})
        if a.protosrc not in cache:
            cache[a.protosrc] = Entry(event.port, packet.src)

    def forward_packet(self, event, dst_port):
        actions = []
        actions.append(of.ofp_action_output(port=dst_port))
        msg = of.ofp_flow_mod(buffer_id=event.ofp.buffer_id, actions=actions)
        event.connection.send(msg)


class Entry:
    def __init__(self, port, mac):
        self.port = port
        self.mac = mac
        self.timeout = time.time() + cfg["controller"]["arp_entry_timeout_seconds"]
