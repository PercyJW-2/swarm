import socket
import socketserver
from typing import Union

from swarm import _string_to_ip_and_port, StandardMessages


class ConnectionManagerTCPHandler(socketserver.BaseRequestHandler):
    """
    Handles Connections from the ConnectionManager.
    Is created by the ConnectionManager during the launch of the socketserver.
    """
    def __init__(self, connection_manager, *args, **kwargs):
        self.connection_manager = connection_manager
        super().__init__(*args, **kwargs)

    # match statement is not available in Python 3.6 :(
    def announce(self, launch_time: str, addr: str):
        """
        Handles new connections.
        1. Establishes new socket to client
        2. Checks if launch time is unique
        3. If not a new launch time is generated
        4. Own launch time and if generated the updated launch time is sent back to the client

        :param launch_time: time when the connecting client launched
        :param addr: address of the socketserver of the connecting client
        """
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
        """
        If a client got an updated launch time it announces its new one to all connected clients.
        Here this time is getting updated

        :param launch_time: updated time when the connecting client started
        :param addr: address of the connecting client
        """
        address_parsed = _string_to_ip_and_port(addr)
        self.connection_manager.connectedIPs[address_parsed] = int(launch_time)

    def heartbeat(self):
        """
        A client always needs to answer the heartbeat message, or it will be removed from the network
        """
        self.send_message(StandardMessages.ACKNOWLEDGED.value)

    def get_addresses(self):
        """
        Sends all addresses of the connected clients to the requester
        """
        address_string =\
            ",".join([addr[0] + ":" + str(addr[1]) for addr in self.connection_manager.connectedIPs.keys()])
        self.send_message(address_string)

    def get_master(self):
        """
        Sends back current master of the network
        """
        master_addr = self.connection_manager.master_addr
        addr_str = master_addr[0] + ":" + str(master_addr[1])
        self.send_message(addr_str)

    def default_case(self, message):
        """
        If a message is not part of the Standard Messages it will be sent to all custom message handlers that are
        listening for new messages. If a handler returns a string it will be sent to the client.

        :param message: complete received message from client
        """
        for func in self.connection_manager.listeners:
            return_msg = func(message)
            if return_msg is not None:
                self.send_message(return_msg)

    def handle(self):
        """
        Handles all incoming messages and parses them from following schema: [Command:arg,arg,...]
        """
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
        """
        Parses provided message to bytes and sends the message back to the client

        :param message: message that will be parsed and sent
        """
        message = str(message).encode("utf-8")
        self.request.sendall(message)
