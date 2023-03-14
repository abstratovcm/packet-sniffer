from functions.unpack import *

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def show_tcp(data):
    (src_port, dest_port, sequence, acknowledgement, flags, data) = unpack_tcp(data)
    print(TAB_1 + 'TCP Segment:')
    print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
    print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgement))
    print(TAB_2 + 'Flags:')
    print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flags[0], flags[1],
                                                                                flags[2], flags[3],
                                                                                flags[4], flags[5]))
    print(TAB_2 + 'Data:')
    print(format_multi_line(DATA_TAB_3, data))
    return src_port, dest_port, sequence, \
           acknowledgement, flags, data

def show_icmp(data):
    icmp_type, code, checksum, data = unpack_icmp(data)
    print(TAB_1 + 'ICMP Packet:')
    print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
    print(TAB_2 + 'Data:')
    print(format_multi_line(DATA_TAB_3, data))
    return icmp_type, code, checksum, data

def show_udp(data):
    src_port, dest_port, length, data = unpack_udp(data)
    print(TAB_1 + 'UDP Segment:')
    print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
    print(TAB_2 + 'Data:')
    print(format_multi_line(DATA_TAB_3, data))
    return src_port, dest_port, length, data

def show_other(data):
    print(TAB_2 + 'Data:')
    print(format_multi_line(DATA_TAB_3, data))
    return data

def show_ipv4(data):
    (version, header_length, ttl, proto, src, target, data) = unpack_ipv4(data)
    print(TAB_1 + 'IPv4 Packet:')
    print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
    print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
    return version, header_length, ttl, proto, src, target, data

def show_ethernet(data):
    dest_mac, src_mac, eth_proto, data = unpack_ethernet(data)
    print('\nEthernet Frame')
    print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
    return dest_mac, src_mac, eth_proto, data
