import socket
import struct
from functions.format import *


# unpacks ethernet frame
def unpack_ethernet(data):
    # receiver (6byte), sender (6byte), type (2byte): ('! 6s 6s H')
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return format_ipv4_address(dest_mac), format_mac_address(src_mac), socket.htons(proto), data[14:]

# unpacks IPv4 packet
def unpack_ipv4(data):
    # IP header
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ipv4_address(src), format_ipv4_address(target), data[header_length:]

# unpacks ICMP address
def unpack_icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# unpacks TCP segment
def unpack_tcp(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = unpack_flags(offset_reserved_flags)
    return src_port, dest_port, sequence, acknowledgement, flags, data[offset:]

# unpacks TCP flags
def unpack_flags(offset_reserved_flags):
    flags = [(offset_reserved_flags & 32) >> 5, (offset_reserved_flags & 16) >> 4,
             (offset_reserved_flags & 8) >> 3, (offset_reserved_flags & 4) >> 2,
             (offset_reserved_flags & 2) >> 1, offset_reserved_flags & 1]
    return flags


# unpacks UDP segment
def unpack_udp(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]