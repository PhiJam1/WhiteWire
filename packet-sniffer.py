# Based off of this docuement https://www.uv.mx/personal/angelperez/files/2018/10/sniffers_texto.pdf

import socket # part of the standard python lib
import struct
from struct import *
import sys
MAX_BUFFER_SIZE = 65565

'''
Ideas: 
allow for ipv4 vs ipv6 packet capture
dev mode for the type of socket (what more info is in there?), rather than raw
switch protocals?
'''

def mac_addr(bytes_addr):
    return ':'.join('%02x' % b for b in bytes_addr)
def get_ip(addr):
    return '.'.join(map(str, addr))


def ipv4_header(raw_data):
    version_header_len = raw_data[0]
    version = version_header_len >> 4
    header_length = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    data = raw_data[header_length:]
    return version, header_length, ttl, proto, src, target, data

# this will parse the ethernet frame
# dest: 1 - 6 btyes, src: 7 - 12, # protocal : 13-14 bytes  
def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = mac_addr(dest)
    src_mac = mac_addr(src)
    proto = socket.htons(prototype)
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data

def main():
    # create raw socket with IPv4
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    while True:
        raw_data, addr = s.recvfrom(MAX_BUFFER_SIZE)
        eth = ethernet_head(raw_data)
        print("\nEthernet Frame:")
        print("Dest: {}, Src: {}, Protocal: {}".format(eth[0], eth[1], eth[2]))
        if eth[2] == 8:
            ipv4 = ipv4_header(eth[4])
            print( '\t - ' + 'IPv4 Packet:')
            print("\t\t - ' + 'Version: {}, Header Length: {}, TTL: {},".format(ipv4[1], ipv4[2], ipv4[3]))
            print("\t\t - ' + 'Protocol: {}, Source: {}, Target: {}".format(ipv4[4], ipv4[5], ipv4[6]))
            break
main()

