from scapy.all import sniff
import argparse

FORMATTING = "\t\t\t"

#helper functions:
def convert_hex_to_bin(hex_string):
    bin_string = "{0:04b}".format(int(hex_string, 16)) 
    return bin_string

def make_addr_readable(hex_data, len):
    readable = ':'.join(hex_data[i:i+2] for i in
    range(0, len, 2))
    return readable

def make_addr_decimal(readable_hex):
    hex_string = readable_hex
    hex_parts = hex_string.split(":")
    decimal_parts = [int(part, 16) for part in hex_parts[:-1]]
    last_decimal = int(hex_parts[-1], 16)
    ip_address = ".".join(map(str, decimal_parts + [last_decimal]))
    return ip_address

def packet_callback(packet):
    raw_data = bytes(packet)
    hex_data = raw_data.hex()

    print(f"\nCaptured Packet (hex): {hex_data}")
    parse_ethernet_header(hex_data)

def capture_packets(interface, capture_filter, packet_count):
    print(f"Starting packet capture on {interface} with filter: {capture_filter}")
    sniff(iface=interface, filter=capture_filter,
    prn=packet_callback, count=packet_count)

def parse_ethernet_header(hex_data):
    # Ethernet header is the first 14 bytes (28 hex characters)
    dest_mac = hex_data[0:12]
    source_mac = hex_data[12:24]
    ether_type = hex_data[24:28]
    # Convert hex MAC addresses to human-readable format
    dest_mac_readable = ':'.join(dest_mac[i:i+2] for i in
    range(0, 12, 2))
    source_mac_readable = ':'.join(source_mac[i:i+2] for i
    in range(0, 12, 2))
    print(f"Destination MAC: {dest_mac_readable}")
    print(f"Source MAC: {source_mac_readable}")
    print(f"EtherType: {ether_type}")
    protocol, num = parse_packet_type(ether_type, hex_data[28:])
    print(protocol,num)
    parse_protocol(protocol, hex_data[(num+28):])

def parse_packet_type(ether_type, hex_data):
    match ether_type:
        case "0800":
            return parse_IPV4(hex_data)
        
        case "0806":
            return parse_ARP(hex_data)

        case "86dd":
            return parse_IPV6(hex_data)

#parse packets:

def parse_IPV4(hex_data):
    print(f"\t---------- IPV4 PACKET ----------")
    protocol = hex_data[18:20]
    print(f"Version: {FORMATTING} {hex_data[0]} {FORMATTING} DV: {int(hex_data[0], 16)}")
    print(f"Header Length: {FORMATTING} {hex_data[1]} {FORMATTING} DV: {int(hex_data[1], 16)}")
    print(f"TOS: \t{FORMATTING} {hex_data[2:4]} {FORMATTING} DV: {int(hex_data[2:4], 16)}")
    print(f"Total Length: {FORMATTING} {hex_data[4:8]} {FORMATTING} DV: {int(hex_data[4:8], 16)}")
    print(f"Checksum: {FORMATTING} {hex_data[8:12]} {FORMATTING} DV: {int(hex_data[8:12], 16)}")
    calculate_IPV4_flags(hex_data[12:16])
    print(f"TTL: \t{FORMATTING}{hex_data[16:18]} {FORMATTING}DV: {int(hex_data[16:18], 16)}")
    print(f"Protocol: {FORMATTING}{protocol} {FORMATTING}DV: {int(protocol, 16)}")
    print(f"Checksum: {FORMATTING}{hex_data[20:24]} {FORMATTING}DV: {int(hex_data[20:24], 16)}")
    
    readable_source_addr = make_addr_readable(hex_data[24:32],8)
    readable_dest_addr = make_addr_readable(hex_data[32:40],8)
    print(f"Source Address: {FORMATTING}{readable_source_addr } \tDV: {make_addr_decimal(readable_source_addr)}")
    print(f"Destination Address: {FORMATTING}{readable_dest_addr} \tDV: {make_addr_decimal(readable_dest_addr)}")
    return (protocol,40)

def calculate_IPV4_flags(flags_offset):
    flag_string = convert_hex_to_bin(flags_offset[0])
    print(f"Flags + offset: {flags_offset}")
    print(f"\tReserved: {flag_string[0]}")
    print(f"\tDont Fragment: {flag_string[1]}")
    print(f"\tMore Fragment: {flag_string[2]}")
    print(f"Offset: {flag_string[3]} {convert_hex_to_bin(flags_offset[1])} {convert_hex_to_bin(flags_offset[2])} {convert_hex_to_bin(flags_offset[3])}")

def parse_ARP(hex_data):
    protocol = hex_data[4:8]
    print(f"\t---------- ARP PACKET ----------")
    print(f"HW Address Type: {hex_data[0:4]} {FORMATTING} DV: {int(hex_data[0:4], 16)}")
    print(f"Protocol Type: {hex_data[4:8]} {FORMATTING} DV: {int(hex_data[4:8], 16)}")
    print(f"HW Address Length: {hex_data[8:10]} {FORMATTING} DV: {int(hex_data[8:10], 16)}")
    print(f"Protocol Address Length: {hex_data[10:12]} {FORMATTING} DV: {int(hex_data[10:12], 16)}")
    print(f"Opcode: {hex_data[12:16]} {FORMATTING} DV: {int(hex_data[12:16], 16)}")

    readable_sourceHW = make_addr_readable(hex_data[16:28], 12)
    print(f"Source HW Address: {readable_sourceHW} {FORMATTING} DV: {make_addr_decimal(readable_sourceHW)}")

    readable_source_proto = make_addr_readable(hex_data[28:36],8)
    print(f"Source Protocol Address: {readable_source_proto} {FORMATTING} DV: {make_addr_decimal(readable_source_proto)}")

    readable_target_HW = make_addr_readable(hex_data[36:48],12)
    print(f"Target HW Address: {readable_target_HW} {FORMATTING} DV: {make_addr_decimal(readable_target_HW)}")

    readable_target_proto = make_addr_readable(hex_data[48:56],8)
    print(f"Target Protocol Address: {readable_target_proto} {FORMATTING} DV: {make_addr_decimal(readable_target_proto)}")
    return (protocol, 56)

def parse_IPV6(hex_data):
    protocol = hex_data[11:13]
    print(f"\t---------- IPV6 PACKET ----------")
    print(f"Version: {hex_data[0]} ")
    print(f"Traffic class: {hex_data[1:2]}")
    print(f"Flow label: {hex_data[2:7]}")
    print(f"Payload Length: {hex_data[7:11]}")
    print(f"Next Header: {hex_data[11:13]}")
    print(f"Hop Limit: {hex_data[13:15]}")
    print(f"Source IP Address: {hex_data[15:47]}")
    print(f"Destination IP Address: {hex_data[47:79]}")
    return (protocol, 79)

#parse protocols:

def parse_protocol(protocol, hex_data):
    match (protocol):
        case "06":
            parse_TCP(hex_data)
        
        case "11":
            parse_UDP(hex_data)
            

def parse_TCP(hex_data):
    print(f"\t---------- TCP PACKET ----------")
    print(f"Source Port: {hex_data[:4]} {FORMATTING} DV: {int(hex_data[:4], 16)}")
    print(f"Destination Port: {hex_data[4:8]}{FORMATTING} DV: {int(hex_data[4:8], 16)}")
    print(f"Sequence Number: {hex_data[8:16]} {FORMATTING} DV: {int(hex_data[8:16], 16)}")
    print(f"Acknowledgement Number: {hex_data[16:24]} {FORMATTING} DV: {int(hex_data[16:24], 16)}")
    print(f"Header Length: {hex_data[24]} {FORMATTING} DV: {int(hex_data[24], 16)}")
    print(f"Reserved: {hex_data[25]} {FORMATTING} DV: {int(hex_data[25], 16)}")
    print(f"Flags: {hex_data[26:28]} {FORMATTING} DV: {int(hex_data[26:28], 16)}")
    calculate_TCP_flags(hex_data[26:28])
    print(f"Window Size: {hex_data[28:32]} {FORMATTING} DV: {int(hex_data[28:32], 16)}")
    print(f"CheckSum: {hex_data[32:36]} {FORMATTING} DV: {int(hex_data[32:36], 16)}")
    print(f"Urgent Pointer: {hex_data[36:40]} {FORMATTING} DV: {int(hex_data[36:40], 16)}")
    header_length = int(hex_data[24], 16) - 5
    print(f"Options: {hex_data[40:40+(header_length*8)]} {FORMATTING} DV: {int(hex_data[40:40+header_length], 16)}")
    print(f"Data: {hex_data[40+header_length:]} {FORMATTING} ")


def calculate_TCP_flags(flag):
    first_val = convert_hex_to_bin(flag[0])
    second_val = convert_hex_to_bin(flag[1])
    print(f"\tCWR: {first_val[0]}")
    print(f"\tECE: {first_val[1]}")
    print(f"\tURG: {first_val[2]}")
    print(f"\tACK: {first_val[3]}")

    print(f"\tPSH: {second_val[0]}")
    print(f"\tRES: {second_val[1]}")
    print(f"\tSYN: {second_val[2]}")
    print(f"\tFIN: {second_val[3]}")

def parse_UDP(hex_data):
    print(f"\t---------- UDP PACKET ----------")
    print(f"Source Port: {hex_data[0:4]} {FORMATTING} DV: {int(hex_data[0:4], 16)}")
    print(f"Destination Port: {hex_data[4:8]} {FORMATTING} DV: {int(hex_data[4:8], 16)}")
    print(f"Length: {hex_data[8:12]} {FORMATTING} DV: {int(hex_data[8:12], 16)}")
    print(f"Checksum: {hex_data[12:16]} {FORMATTING} DV: {int(hex_data[12:16], 16)}")


def main():
    interface = 'wlan0'
    arg_filter = 'arp'
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help = "interface to use")
    parser.add_argument("-f","--filter", help = "Capture filter")
    args = parser.parse_args()
    if(args.interface):
        interface = args.interface
        print(args.interface)
    
    if(args.filter):
        arg_filter = args.filter
        print(args.filter)
    capture_packets(interface, arg_filter, 1)

main()