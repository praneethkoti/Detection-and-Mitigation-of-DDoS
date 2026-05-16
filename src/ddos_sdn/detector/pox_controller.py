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

import datetime
import time
from pox.core import core
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.revent import *
import pox.openflow.libopenflow_01 as of
from pox.lib.recoco import Timer

from ddos_sdn.config import load_config
from ddos_sdn.detector.entropy import EntropyAnalyzer

cfg = load_config()
entropy_instance = EntropyAnalyzer()
port_stats = {}

log = core.getLogger()

def monitor_ddos(event):
    global port_stats

    if event.connection.dpid not in port_stats:
        port_stats[event.connection.dpid] = {}
    if event.port not in port_stats[event.connection.dpid]:
        port_stats[event.connection.dpid][event.port] = 1
    else:
        port_stats[event.connection.dpid][event.port] += 1

    log.info(f"Switch {event.connection.dpid}, Port {event.port}, Count {port_stats[event.connection.dpid][event.port]}")

def check_ddos():
    global port_stats
    threshold = cfg["detector"]["port_count_threshold"]
    for switch, ports in port_stats.items():
        for port, count in ports.items():
            if count >= threshold:
                log.info(f"DDOS detected on Switch {switch}, Port {port}. Dropping packets...")
                msg = of.ofp_packet_out(in_port=port)
                core.openflow.sendToDPID(switch, msg)

    port_stats = {}

class L3Switch(EventMixin):
    def __init__(self, fake_gws=[], arp_for_unknowns=False):
        self.fake_gateways = set(fake_gws)
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

class Entry(object):
    def __init__(self, port, mac):
        self.port = port
        self.mac = mac
        self.timeout = time.time() + cfg["controller"]["arp_entry_timeout_seconds"]
