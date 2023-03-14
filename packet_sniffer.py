import socket

from functions.show import *

# create a socket object
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

while True:
    # receive packets
    packet, address = sock.recvfrom(65535)
    dest_mac, src_mac, eth_proto, data = show_ethernet(packet)

    # 8 for IPv4
    if eth_proto == 8:
        (version, header_length, ttl, proto, src, target, data) = show_ipv4(data)

        # ICMP
        if proto == 1:
            show_icmp(data)

        # TCP
        elif proto == 6:
            show_tcp(data)

        # UDP
        elif proto == 17:
            show_udp(data)

        # other
        else:
            show_other(data)










