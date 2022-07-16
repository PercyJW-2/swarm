import socket
import socketserver
import time
import threading
from enum import Enum
import re


class NetworkAddressType(Enum):
    IPV6 = 0
    IPV4 = 1


class StandardMessages(Enum):
    ANNOUNCE = "announce"
    ACKNOWLEDGED = "acknowledged"
    HEARTBEAT = "heartbeat"
    GET_ADDRESSES = "addresses"
    GET_MASTER = "master"
    GET_LOGIN_TIME = "login_time"


class MessageToBig(Exception):
    pass


class InvalidIPString(Exception):
    pass


class ConnectionManager:
    def __init__(self,
                 addr="localhost",
                 port=6969,
                 heartbeat=1,
                 buffer_size=1024):
        self.addr = addr
        self.port = port
        self.heartbeat = heartbeat
        self.buffer_size = buffer_size

        self.creation_time = time.time_ns()

        self.socket = None
        self.connectedIPs = {}
        self.socketServerThread = None
        self.heartbeatThread = None
        self.master_addr = None

    @staticmethod
    def _launch_socket_server(address, request_handler=socketserver.BaseRequestHandler):
        with socketserver.UDPServer(address, request_handler) as server:
            server.serve_forever()

    def _launch_heartbeat(self):
        heartbeat_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while True:
            to_be_deleted = []
            for address in self.connectedIPs.keys():
                heartbeat_socket.sendto(bytes(StandardMessages.HEARTBEAT.value, "utf-8"), address)
                try:
                    received = str(heartbeat_socket.recv(self.buffer_size), "utf-8")
                    if received.lower() != StandardMessages.ACKNOWLEDGED.value:
                        to_be_deleted.append(address)
                except ConnectionResetError:
                    to_be_deleted.append(address)
            for address in to_be_deleted:
                self.connectedIPs.pop(address)
            if self.master_addr not in self.connectedIPs.keys() and self.master_addr != (self.addr, self.port):
                self.master_addr = max(self.connectedIPs, key=self.connectedIPs.get)
            time.sleep(self.heartbeat)

    def _connect_to_clients(self, ip_list):
        for (ip, port) in ip_list:
            self.socket.sendto(bytes(StandardMessages.ANNOUNCE.value, "utf-8"), (ip, port))
            try:
                received = str(self.socket.recv(self.buffer_size), "utf-8")
                self.connectedIPs[(ip, port)] = received
            except ConnectionResetError:
                pass

    @staticmethod
    def _string_to_ip_and_port(message):
        valid_ipv4 = re.compile(r"^(\d?\d?\d.){3}\d?\d?\d:(\d?){4}\d$")
        valid_ipv6 = re.compile(r"^([a-f\d:]+:+)+[a-f\d]+(\d?){4}\d$")
        if (not valid_ipv4.match(message)) and (not valid_ipv6.match(message)):
            raise InvalidIPString
        msg_split = message.split(":")
        port = msg_split[-1]
        ip = message.replace(":" + port, "")
        port = int(port)
        return ip, port

    def connect(self, ip_list):
        if self.socket is not None:
            return
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._connect_to_clients(ip_list)
        if len(self.connectedIPs) > 0:
            received_msg = self.send_message(StandardMessages.GET_MASTER, next(iter(self.connectedIPs.keys())))
            self.master_addr = self._string_to_ip_and_port(received_msg)
            received_msg = self.send_message(StandardMessages.GET_ADDRESSES, self.master_addr)
            network_ips = [self._string_to_ip_and_port(addr) for addr in received_msg.split(",")]
            network_ips = [addr for addr in network_ips if addr not in self.connectedIPs]
            self._connect_to_clients(network_ips)
        else:
            self.master_addr = (self.addr, self.port)
        self.socketServerThread = threading.Thread(target=self._launch_socket_server, args=((self.addr, self.port),))
        self.socketServerThread.daemon = True
        self.socketServerThread.start()
        self.heartbeatThread = threading.Thread(target=self._launch_heartbeat)
        self.heartbeatThread.daemon = True
        self.heartbeatThread.start()

    def disconnect(self):
        if self.socket is None:
            return
        if self.socketServerThread.is_alive():
            self.socketServerThread.terminate()
        if self.heartbeatThread.is_alive():
            self.heartbeatThread.terminate()

    def send_message(self, message, address):
        if self.socket is None:
            return
        data = bytes(message, "utf-8")
        if len(data) > self.buffer_size:
            raise MessageToBig
        self.socket.sendto(data, address)
        return str(self.socket.recv(self.buffer_size), "utf-8")

    def get_current_addresses(self):
        return self.connectedIPs.keys()

    def get_current_master(self):
        return self.master_addr

    def get_ip(self):
        return self.addr, self.port
