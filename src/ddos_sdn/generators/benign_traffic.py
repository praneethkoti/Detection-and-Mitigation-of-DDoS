import sys
import getopt
import time
from os import popen
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp, IP, UDP, Ether
from random import randint

def generate_source_ip():
    excluded_ranges = [10, 127, 254, 1, 2, 169, 172, 192]

    first_octet = randint(1, 255)
    while first_octet in excluded_ranges:
        first_octet = randint(1, 255)

    ip_address = ".".join([str(first_octet), str(randint(1, 255)), str(randint(1, 255)), str(randint(1, 255))])
    return ip_address

def destination_ip_generator(lower, upper):
    first_octet = 10
    second_octet, third_octet = 0, 0
    ip = ".".join([str(first_octet), str(second_octet), str(third_octet), str(randint(lower, upper))])
    return ip

def main(args):
    print(args)
    try:
        options, arguments = getopt.getopt(sys.argv[1:], 's:e:', ['start=', 'end='])
    except getopt.GetoptError:
        sys.exit(2)

    for option, argument in options:
        if option == '-s':
            start_range = int(argument)
        elif option == '-e':
            end_range = int(argument)

    if not start_range or not end_range:
        sys.exit()

    network_interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read().strip()

    for _ in range(1000):
        packet = Ether() / IP(dst=destination_ip_generator(start_range, end_range), src=generate_source_ip()) / UDP(dport=80, sport=2)
        print(repr(packet))

        sendp(packet, iface=network_interface, inter=0.1)

if __name__ == '__main__':
    main(sys.argv)
