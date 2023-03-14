import textwrap

# returns properly formatted MAC address (AA:BB:CC:DD:EE:FF)
def format_mac_address(bytes_address):
    bytes_str = map('{:02x}'.format, bytes_address)
    return ':'.join(bytes_str).upper()

# returns properly formatted IPv4 address
def format_ipv4_address(address):
    return '.'.join(map(str, address))


# returns properly formatted multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])