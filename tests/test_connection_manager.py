from unittest import TestCase

import swarm
import random
from ipaddress import IPv4Address, IPv6Address


class Test(TestCase):
    def test_ipv4_str_parsing(self):
        for i in range(1000):
            addr_str = str(IPv4Address(random.getrandbits(32)))
            port = random.randint(1, 65535)
            (ip, port_e) = swarm.ConnectionManager._string_to_ip_and_port(addr_str + ":" + str(port))
            self.assertEqual((ip, port_e), (addr_str, port))

    def test_ipv6_str_parsing(self):
        for i in range(1000):
            addr_str = str(IPv6Address(random.getrandbits(128)))
            port = random.randint(1, 65535)
            (ip, port_e) = swarm.ConnectionManager._string_to_ip_and_port(addr_str + ":" + str(port))
            self.assertEqual((ip, port_e), (addr_str, port))

    def test_invalid_str_parsing(self):
        invalid_sting = "invalid"
        try:
            swarm.ConnectionManager._string_to_ip_and_port(invalid_sting)
        except swarm.InvalidIPString:
            return
        self.assertTrue(False)
