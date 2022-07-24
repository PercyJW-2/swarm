import socket
import socketserver
import time
import threading
from enum import Enum
import re
from functools import partial
from typing import List, Callable, Optional, Union, Tuple

try:
    from time import time_ns
except ImportError:
    from datetime import datetime

    def time_ns():
        now = datetime.now()
        return int(now.timestamp() * 1e9)


class StandardMessages(Enum):
    ANNOUNCE = "announce"
    UPDATE_LAUNCH = "update"
    ACKNOWLEDGED = "acknowledged"
    HEARTBEAT = "heartbeat"
    GET_ADDRESSES = "addresses"
    GET_MASTER = "master"


class MessageToBig(Exception):
    pass


class InvalidIPString(Exception):
    pass


class NotInContextManagerMode(Exception):
    pass


class ConnectionManagerTCPHandler(socketserver.BaseRequestHandler):
    def __init__(self, connection_manager, *args, **kwargs):
        self.connection_manager = connection_manager
        super().__init__(*args, **kwargs)

    # match statement is not available in Python 3.6 :(
    def announce(self, launch_time: str, addr: str):
        address_parsed = _string_to_ip_and_port(addr)
        self.connection_manager.sockets[address_parsed] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection_manager.sockets[address_parsed].connect(address_parsed)
        announced_launch_time = int(launch_time)
        updated_launch_time = False
        while announced_launch_time in self.connection_manager.connectedIPs.values():
            updated_launch_time = True
            announced_launch_time = announced_launch_time + 1
        self.connection_manager.connectedIPs[address_parsed] = announced_launch_time
        updated_time = ""
        if updated_launch_time:
            updated_time = "," + str(announced_launch_time)
        self.send_message(str(self.connection_manager.creation_time) + updated_time)

    def update_launch_time(self, launch_time, addr):
        address_parsed = _string_to_ip_and_port(addr)
        self.connection_manager.connectedIPs[address_parsed] = int(launch_time)

    def heartbeat(self):
        self.send_message(StandardMessages.ACKNOWLEDGED.value)

    def get_addresses(self):
        address_string =\
            ",".join([addr[0] + ":" + str(addr[1]) for addr in self.connection_manager.connectedIPs.keys()])
        self.send_message(address_string)

    def get_master(self):
        master_addr = self.connection_manager.master_addr
        addr_str = master_addr[0] + ":" + str(master_addr[1])
        self.send_message(addr_str)

    def default_case(self, message):
        for func in self.connection_manager.listeners:
            return_msg = func(message)
            if return_msg is not None:
                self.send_message(return_msg)

    def handle(self):
        while not self.connection_manager.stop_socketserver:
            msg_recvd = ""
            try:
                msg_recvd = str(self.request.recv(self.connection_manager._buffer_size), "utf-8").lower()
            except ConnectionError:
                pass
            if not msg_recvd:
                break
            msg_split = msg_recvd.split(":")
            cmd = msg_split[0]
            msg = ":".join(msg_split[1:len(msg_split)])
            msg_args = msg.split(",")

            if cmd == StandardMessages.ANNOUNCE.value:
                self.announce(*msg_args)
            elif cmd == StandardMessages.UPDATE_LAUNCH.value:
                self.update_launch_time(*msg_args)
            elif cmd == StandardMessages.HEARTBEAT.value:
                self.heartbeat()
            elif cmd == StandardMessages.GET_MASTER.value:
                self.get_master()
            elif cmd == StandardMessages.GET_ADDRESSES.value:
                self.get_addresses()
            else:
                self.default_case(msg_recvd)

    def send_message(self, message: Union[str, int]):
        message = str(message).encode("utf-8")
        self.request.sendall(message)


def _string_to_ip_and_port(message: str) -> Tuple[str, int]:
    valid_ipv4 = re.compile(r"^(\d?\d?\d.){3}\d?\d?\d:(\d?){4}\d$")
    valid_ipv6 = re.compile(r"^([a-f\d:]+:+)+[a-f\d]+:(\d?){4}\d$")
    valid_address = re.compile(r"^(localhost)|(\*+.\*):(\d?){4}\d$")
    if (not valid_ipv4.match(message)) and (not valid_ipv6.match(message)) and (not valid_address.match(message)):
        raise InvalidIPString(f"'{message}' is not an valid ip address")
    msg_split = message.split(":")
    port = msg_split[-1]
    ip = ":".join(msg_split[0:-1])
    port = int(port)
    return ip, port


class ConnectionManager:
    def __init__(self,
                 addr="localhost",
                 port=6969,
                 heartbeat=1,
                 buffer_size=1024,
                 ip_list=None):
        if ip_list is None:
            ip_list = []
        self._addr = addr
        self._port = port
        self._heartbeat = heartbeat
        self._buffer_size = buffer_size
        self._ip_list: List[str] = ip_list

        self.creation_time = time_ns()

        self.sockets = {}
        self.connectedIPs = {}
        self.socketServerThread = None
        self.heartbeatThread = None
        self.master_addr = (addr, port)
        self.stop_heartbeat = False
        self.stop_socketserver = False
        self.socketServer = None
        self.listeners = []

    def __enter__(self):
        if self._ip_list is None:
            raise NotInContextManagerMode("An IP List needs to be provided to the Constructor to use this class "
                                          "with the 'with' keyword.")
        self.connect(self._ip_list)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def __del__(self):
        self.disconnect()

    def _launch_socket_server(self, address: Tuple[str, int], request_handler=socketserver.BaseRequestHandler):
        socketserver.ThreadingTCPServer.allow_reuse_port = True
        with socketserver.ThreadingTCPServer(address, request_handler) as server:
            self.socketServer = server
            server.serve_forever()

    def _launch_heartbeat(self):
        while not self.stop_heartbeat:
            to_be_deleted = []
            for address in self.connectedIPs.keys():
                try:
                    self.sockets[address].sendall(bytes(StandardMessages.HEARTBEAT.value, "utf-8"))
                    received = str(self.sockets[address].recv(self._buffer_size), "utf-8")
                    if received.lower() != StandardMessages.ACKNOWLEDGED.value:
                        to_be_deleted.append(address)
                except ConnectionError:
                    to_be_deleted.append(address)
            for address in to_be_deleted:
                self.connectedIPs.pop(address)
                self.sockets[address].close()
                self.sockets.pop(address)
            if self.master_addr not in self.connectedIPs.keys() and self.master_addr != (self._addr, self._port):
                if len(self.connectedIPs) == 0:
                    self.master_addr = (self._addr, self._port)
                else:
                    master_candidate = min(self.connectedIPs, key=self.connectedIPs.get)
                    if self.connectedIPs[master_candidate] < self.creation_time:
                        self.master_addr = master_candidate
                    else:
                        self.master_addr = (self._addr, self._port)
            time.sleep(self._heartbeat)

    def _connect_to_clients(self, ip_list: List[Tuple[str, int]]):
        changed_start_time = False
        for (ip, port) in ip_list:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect((ip, port))
                self.sockets[(ip, port)] = sock
                sock.sendall(bytes(
                    StandardMessages.ANNOUNCE.value + ":" +
                    str(self.creation_time) + "," + self._addr + ":" + str(self._port),
                    "utf-8"
                ))
                recv_msg = str(sock.recv(self._buffer_size), "utf-8")
                recv_msgs = recv_msg.split(",")
                self.connectedIPs[(ip, port)] = int(recv_msgs[0])
                if len(recv_msgs) > 1:
                    changed_start_time = True
                    self.creation_time = int(recv_msgs[1])
            except ConnectionRefusedError:
                pass
        if changed_start_time:
            for sock in self.sockets.values():
                sock.sendall(bytes(
                    StandardMessages.UPDATE_LAUNCH.value + ":" +
                    str(self.creation_time) + "," + self._addr + ":" + str(self._port),
                    "utf-8"
                ))

    def connect(self, ip_list: List[str]):
        if len(self.sockets) > 0:
            return
        request_handler = partial(ConnectionManagerTCPHandler, self)
        self.socketServerThread =\
            threading.Thread(target=self._launch_socket_server, args=((self._addr, self._port), request_handler))
        self.socketServerThread.daemon = True
        self.socketServerThread.start()

        self.heartbeatThread = threading.Thread(target=self._launch_heartbeat)
        self.heartbeatThread.daemon = True
        self.heartbeatThread.start()
        ip_list = [_string_to_ip_and_port(addr) for addr in ip_list]
        ip_list = [addr for addr in ip_list if addr != (self._addr, self._port)]
        self._connect_to_clients(ip_list)
        if len(self.connectedIPs) > 0:
            received_msg = self.send_message(StandardMessages.GET_MASTER.value, next(iter(self.connectedIPs.keys())))
            self.master_addr = _string_to_ip_and_port(received_msg)
            received_msg = self.send_message(StandardMessages.GET_ADDRESSES.value, self.master_addr)
            network_ips = [_string_to_ip_and_port(addr) for addr in received_msg.split(",") if addr != ""]
            network_ips = [addr for addr in network_ips if addr not in self.connectedIPs]
            network_ips = [addr for addr in network_ips if addr != (self._addr, self._port)]
            self._connect_to_clients(network_ips)

    def disconnect(self):
        # if len(self.sockets) == 0:
        #     return
        if self.heartbeatThread is not None:
            self.stop_heartbeat = True
        for sock in list(self.sockets.values()):
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        self.sockets.clear()
        if self.socketServerThread is not None:
            self.stop_socketserver = True
            self.socketServer.shutdown()

    def send_message(self, message: str, address: Tuple[str, int]):
        if self.sockets.get(address) is None:
            return
        data = bytes(message, "utf-8")
        if len(data) > self._buffer_size:
            raise MessageToBig
        self.sockets[address].sendall(data)
        return str(self.sockets[address].recv(self._buffer_size), "utf-8")

    def get_current_addresses(self):
        return list(self.connectedIPs.keys())

    def get_current_master(self):
        return self.master_addr

    def get_ip(self):
        return self._addr, self._port

    def add_listener(self, function: Callable[[str], Optional[str]]):
        self.listeners.append(function)

    def remove_listener(self, function: Callable[[str], Optional[str]]):
        self.listeners.remove(function)
