import socket
import struct
import textwrap

SOCKET_BUFF_SIZE = 65536
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '
TAB_5 = '\t\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '
DATA_TAB_5 = '\t\t\t\t\t '


# function that will format the mac address to a human readable form
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# return properly formatted IPv4 address
def ipv4(addr):
    return ''.join(map(str, addr))


# upack the 14 byte ethernet frame
def ethernet_frame(data):
    # each mac address is 6 bytes, prototype is 2 bytes
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Unpack IPv$ packet
def ipv4_packet(data):
    version_header_length = data[0]
    # right shift by 4 bytes to remove the IHL (Header Len)
    version = version_header_length >> 4  

    # 15 -> 00001111 AND by this mask to remove the version info
    header_length = (version_header_length & 0b00001111) * 4
    time_to_live, ip_proto, src_ip, target_ip = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, time_to_live, ip_proto, ipv4(src_ip), ipv4(target_ip), data[header_length:]

# function to help with formating
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size & 2:
            size -=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

# unpack the ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[:4]

# Unpack TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, ack, offset_reversed_flags) = struct.unpack('! H H L L H', data[:14])
    offset = offset_reversed_flags >> 12 * 4
    flag_urg = (offset_reversed_flags & 0b00100000) >> 5
    flag_ack = (offset_reversed_flags & 0b00010000) >> 4
    flag_psh = (offset_reversed_flags & 0b00001000) >> 3
    flag_rst = (offset_reversed_flags & 0b00000100) >> 2
    flag_syn = (offset_reversed_flags & 0b00000010) >> 1
    flag_fin = offset_reversed_flags & 0b00000001
    return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


def main():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True: 
        raw_data, addr = sock.recvfrom(SOCKET_BUFF_SIZE)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\nEthernet Frame:")
        print(TAB_1 + "Dest: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))

        # 8 FOR IPv4
        if eth_proto == 8:
            (version, header_length, time_to_live, ip_proto, src_ip, target_ip, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet')
            print(TAB_2, 'Version: {} Header Len: {}, Time to Live: {}'.format(version, header_length , time_to_live))
            print(TAB_2, 'Protocol: {} Src: {}, Target: {}'.format(ip_proto, src_ip, target_ip))
            
            # ICMP
            if ip_proto == 1:
                (icmp_type, code, checksum, data) = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                print(TAB_2 + "Data:")
                print(format_multi_line(DATA_TAB_3, data))

            # TCP
            elif ip_proto == 6:
                (src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Src Port: {}, Dest Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, ack))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACL: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))
            
            # udp
            elif ip_proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Src Port: {}, Dest Port: {}, Length: {}'.format(src_port, dest_port, length))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

                # Other
            else:
                print(TAB_1 + "Unrecognized ip protocol")
                print(TAB_1 + 'Raw Data:')
                print(format_multi_line(DATA_TAB_2, data))

main()