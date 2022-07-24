from unittest import TestCase

import swarm
import random
from ipaddress import IPv4Address, IPv6Address
from typing import List


class TestStatics(TestCase):
    def test_ipv4_str_parsing(self):
        for i in range(1000):
            addr_str = str(IPv4Address(random.getrandbits(32)))
            port = random.randint(1, 65535)
            (ip, port_e) = swarm._string_to_ip_and_port(addr_str + ":" + str(port))
            self.assertEqual((ip, port_e), (addr_str, port))

    def test_ipv6_str_parsing(self):
        for i in range(1000):
            addr_str = str(IPv6Address(random.getrandbits(128)))
            port = random.randint(1, 65535)
            (ip, port_e) = swarm._string_to_ip_and_port(addr_str + ":" + str(port))
            self.assertEqual((ip, port_e), (addr_str, port))

    def test_invalid_str_parsing(self):
        invalid_sting = "invalid"
        try:
            swarm._string_to_ip_and_port(invalid_sting)
        except swarm.InvalidIPString:
            return
        self.assertTrue(False)


class TestConnections(TestCase):
    def test_initial_connection(self):
        conn_mans = {}
        for i in range(10):
            conn_mans[("localhost:" + str(1000 + i))] = swarm.ConnectionManager(port=1000 + i)

        addresses = list(conn_mans.keys())
        to_connect: List[str] = []
        for i in range(len(addresses)):
            conn_mans[addresses[i]].connect(to_connect)
            to_connect.append(addresses[i])

        master = swarm._string_to_ip_and_port(addresses[0])
        for manager in conn_mans.values():
            self.assertEqual(master, manager.get_current_master())
        for manager in conn_mans.values():
            manager.disconnect()
