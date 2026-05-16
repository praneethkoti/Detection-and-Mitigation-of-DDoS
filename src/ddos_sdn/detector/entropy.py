import logging
import math

try:
    from pox.core import core
    logger = core.getLogger()
except ImportError:
    logger = logging.getLogger(__name__)


class EntropyAnalyzer:
    def __init__(self):
        self.packet_count = 0
        self.entropy_dict = {}
        self.ip_addresses = []
        self.dst_entropy = []
        self.entropy_value = 1.0

    def collect_statistics(self, ip):
        self.packet_count += 1
        self.ip_addresses.append(ip)

        if self.packet_count == 50:
            unique_ips = set(self.ip_addresses)
            for addr in unique_ips:
                if addr not in self.entropy_dict:
                    self.entropy_dict[addr] = 0
                self.entropy_dict[addr] += self.ip_addresses.count(addr)
            self.calculate_entropy(self.entropy_dict)
            logger.info(self.entropy_dict)
            self.reset_stats()

    def calculate_entropy(self, address_stats):
        total_packets = 50
        entropy_values = []
        for _, count in address_stats.items():
            proportion = count / float(total_packets)
            proportion = abs(proportion)
            entropy_values.append(-proportion * math.log(proportion, 10))

        entropy_sum = sum(entropy_values)
        logger.info(f'Entropy: {entropy_sum}')
        self.dst_entropy.append(entropy_sum)
        if len(self.dst_entropy) == 80:
            print(self.dst_entropy)
            self.dst_entropy = []
        self.entropy_value = entropy_sum

    def reset_stats(self):
        self.entropy_dict = {}
        self.ip_addresses = []
        self.packet_count = 0
