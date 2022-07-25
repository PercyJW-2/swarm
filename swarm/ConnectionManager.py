import socket
import socketserver
import time
import threading
from functools import partial
from typing import List, Callable, Optional, Tuple

from .statics import StandardMessages, MessageToBig, _string_to_ip_and_port
from .ConnectionManagerTCPHandler import ConnectionManagerTCPHandler

try:
    from time import time_ns
except ImportError:
    from datetime import datetime

    def time_ns():
        now = datetime.now()
        return int(now.timestamp() * 1e9)


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
        self.connect(self._ip_list)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def __del__(self):
        self.disconnect()

    def _launch_socket_server(self, address: Tuple[str, int], request_handler=socketserver.BaseRequestHandler):
        socketserver.ThreadingTCPServer.allow_reuse_port = True
        socketserver.ThreadingTCPServer.allow_reuse_address = True
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
            if self.socketServer is not None:
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
