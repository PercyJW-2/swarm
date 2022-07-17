import socket
import socketserver
import time
import threading
from enum import Enum
import re
from functools import partial


class StandardMessages(Enum):
    ANNOUNCE = "announce"
    ACKNOWLEDGED = "acknowledged"
    HEARTBEAT = "heartbeat"
    GET_ADDRESSES = "addresses"
    GET_MASTER = "master"


class MessageToBig(Exception):
    pass


class InvalidIPString(Exception):
    pass


class ConnectionManagerTCPHandler(socketserver.BaseRequestHandler):
    def __init__(self, connection_manager, *args, **kwargs):
        self.connection_manager = connection_manager
        super().__init__(*args, **kwargs)

    # match statement is not available in Python 3.6 :(
    def announce(self, launch_time, addr):
        address_parsed = _string_to_ip_and_port(addr)
        self.connection_manager.sockets[address_parsed] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection_manager.sockets[address_parsed].connect(address_parsed)
        self.connection_manager.connectedIPs[address_parsed] = int(launch_time)
        self.send_message(str(self.connection_manager.creation_time))

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
            msg_recvd = str(self.request.recv(self.connection_manager.buffer_size), "utf-8").lower()
            if not msg_recvd:
                break
            msg_split = msg_recvd.split(":")
            cmd = msg_split[0]
            msg = ":".join(msg_split[1:len(msg_split)])
            msg_args = msg.split(",")

            if cmd == StandardMessages.ANNOUNCE.value:
                self.announce(*msg_args)
            elif cmd == StandardMessages.HEARTBEAT.value:
                self.heartbeat()
            elif cmd == StandardMessages.GET_MASTER.value:
                self.get_master()
            elif cmd == StandardMessages.GET_ADDRESSES.value:
                self.get_addresses()
            else:
                self.default_case(msg_recvd)

    def send_message(self, message):
        message = str(message).encode("utf-8")
        self.request.sendall(message)


def _string_to_ip_and_port(message):
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
                 buffer_size=1024):
        self.addr = addr
        self.port = port
        self.heartbeat = heartbeat
        self.buffer_size = buffer_size

        self.creation_time = time.time_ns()

        self.sockets = {}
        self.connectedIPs = {}
        self.socketServerThread = None
        self.heartbeatThread = None
        self.master_addr = (addr, port)
        self.stop_heartbeat = False
        self.stop_socketserver = False
        self.socketServer = None

    def __del__(self):
        for sock in self.sockets.values():
            sock.close()

    def _launch_socket_server(self, address, request_handler=socketserver.BaseRequestHandler):
        with socketserver.ThreadingTCPServer(address, request_handler) as server:
            self.socketServer = server
            server.serve_forever()

    def _launch_heartbeat(self):
        while not self.stop_heartbeat:
            to_be_deleted = []
            for address in self.connectedIPs.keys():
                try:
                    self.sockets[address].sendall(bytes(StandardMessages.HEARTBEAT.value, "utf-8"))
                    received = str(self.sockets[address].recv(self.buffer_size), "utf-8")
                    if received.lower() != StandardMessages.ACKNOWLEDGED.value:
                        to_be_deleted.append(address)
                except ConnectionAbortedError:
                    to_be_deleted.append(address)
            for address in to_be_deleted:
                self.connectedIPs.pop(address)
                self.sockets[address].close()
                self.sockets.pop(address)
            if self.master_addr not in self.connectedIPs.keys() and self.master_addr != (self.addr, self.port):
                if len(self.connectedIPs) > 0:
                    self.master_addr = (self.addr, self.port)
                else:
                    self.master_addr = max(self.connectedIPs, key=self.connectedIPs.get)
            time.sleep(self.heartbeat)

    def _connect_to_clients(self, ip_list):
        for (ip, port) in ip_list:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect((ip, port))
                self.sockets[(ip, port)] = sock
                sock.sendall(bytes(
                    StandardMessages.ANNOUNCE.value + ":" +
                    str(self.creation_time) + "," + self.addr + ":" + str(self.port),
                    "utf-8"
                ))
                self.connectedIPs[(ip, port)] = str(sock.recv(self.buffer_size), "utf-8")
            except ConnectionRefusedError:
                pass

    def connect(self, ip_list):
        if len(self.sockets) > 0:
            return
        request_handler = partial(ConnectionManagerTCPHandler, self)
        self.socketServerThread =\
            threading.Thread(target=self._launch_socket_server, args=((self.addr, self.port), request_handler))
        self.socketServerThread.daemon = True
        self.socketServerThread.start()
        self.heartbeatThread = threading.Thread(target=self._launch_heartbeat)
        self.heartbeatThread.daemon = True
        self.heartbeatThread.start()
        self._connect_to_clients(ip_list)
        if len(self.connectedIPs) > 0:
            received_msg = self.send_message(StandardMessages.GET_MASTER.value, next(iter(self.connectedIPs.keys())))
            self.master_addr = _string_to_ip_and_port(received_msg)
            received_msg = self.send_message(StandardMessages.GET_ADDRESSES.value, self.master_addr)
            network_ips = [_string_to_ip_and_port(addr) for addr in received_msg.split(",") if addr != ""]
            network_ips = [addr for addr in network_ips if addr not in self.connectedIPs]
            network_ips = [addr for addr in network_ips if addr != (self.addr, self.port)]
            self._connect_to_clients(network_ips)

    def disconnect(self):
        if len(self.sockets) == 0:
            return
        if self.socketServerThread.is_alive():
            self.stop_socketserver = True
            self.socketServer.shutdown()
        if self.heartbeatThread.is_alive():
            self.stop_heartbeat = True

    def send_message(self, message, address):
        print(f"{message} is sent to {address}")
        if self.sockets.get(address) is None:
            return
        data = bytes(message, "utf-8")
        if len(data) > self.buffer_size:
            raise MessageToBig
        self.sockets[address].sendall(data)
        return str(self.sockets[address].recv(self.buffer_size), "utf-8")

    def get_current_addresses(self):
        return self.connectedIPs.keys()

    def get_current_master(self):
        return self.master_addr

    def get_ip(self):
        return self.addr, self.port
