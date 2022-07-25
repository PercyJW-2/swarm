from unittest import TestCase

import swarm
import random
import socket
from ipaddress import IPv4Address, IPv6Address
from typing import List

import swarm.statics


class TestStatics(TestCase):
    def test_ipv4_str_parsing(self):
        for i in range(1000):
            addr_str = str(IPv4Address(random.getrandbits(32)))
            port = random.randint(1, 65535)
            (ip, port_e) = swarm.statics._string_to_ip_and_port(addr_str + ":" + str(port))
            self.assertEqual((ip, port_e), (addr_str, port))

    def test_ipv6_str_parsing(self):
        for i in range(1000):
            addr_str = str(IPv6Address(random.getrandbits(128)))
            port = random.randint(1, 65535)
            (ip, port_e) = swarm.statics._string_to_ip_and_port(addr_str + ":" + str(port))
            self.assertEqual((ip, port_e), (addr_str, port))

    def test_invalid_str_parsing(self):
        invalid_sting = "invalid"
        try:
            swarm.statics._string_to_ip_and_port(invalid_sting)
        except swarm.statics.InvalidIPString:
            return
        self.assertTrue(False)


def get_port(initial_port: int) -> int:
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(("localhost", initial_port)) == 0:
                initial_port += 1
            else:
                return initial_port


class TestConnections(TestCase):
    def test_initial_connection(self):
        conn_mans = {}
        to_connect: List[str] = []
        for i in range(10):
            possible_port = get_port(1000 + i)
            ip_str = "localhost:" + str(possible_port)
            conn_mans[ip_str] = swarm.ConnectionManager(port=possible_port)
            conn_mans[ip_str].connect(to_connect)
            to_connect.append(ip_str)

        master = swarm.statics._string_to_ip_and_port(to_connect[0])
        for manager in conn_mans.values():
            self.assertEqual(master, manager.get_current_master())
        for manager in conn_mans.values():
            manager.disconnect()
