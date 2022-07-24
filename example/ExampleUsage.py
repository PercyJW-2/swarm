#!/usr/bin/python3

from swarm import ConnectionManager
import sys
from time import sleep
import yaml


def parse_ip(ip_str):
    split_str = ip_str.split(":")
    port = split_str[-1]
    ip = ":".join(split_str[0:-1])
    port = int(port)
    return ip, port


if __name__ == "__main__":
    if len(sys.argv) != 2:
        exit(-1)
    with open("ip_list.yaml", "r") as stream:
        try:
            data = yaml.safe_load(stream)
            ips = data['ips']

            index = int(sys.argv[1])
            if index < 0 or index >= len(ips):
                exit(-2)
            ip_source, port_source = parse_ip(ips[index])

            connManInit = ConnectionManager(addr=ip_source, port=port_source, ip_list=ips)

            with connManInit as connMan:
                try:
                    while True:
                        print("\033[H\033[J", end="")
                        print(f"current master: {connMan.get_current_master()}")
                        print(f"client address: {ips[index]}")
                        print(f"Is Client Master? {connMan.get_current_master() == (ip_source, port_source)}")
                        print(f"connected IPs: {connMan.get_current_addresses()}")
                        sleep(1)
                except KeyboardInterrupt:
                    print("exiting...")
        except yaml.YAMLError as exc:
            print(exc)
