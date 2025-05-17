import socket
import struct
import binascii
import pandas as pd
from collections import defaultdict
import platform

def create_socket():
    os_name = platform.system()
    try:
        if os_name == "Linux":
            # Unix/Linux: Use AF_PACKET to capture raw Ethernet frames
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        elif os_name == "Windows":
            # Windows: Use AF_INET to capture IP packets
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind(('0.0.0.0', 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Enable promiscuous mode
            SIO_RCVALL = 0x98000001
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            raise OSError("Unsupported OS")
        return s, os_name
    except PermissionError as e:
        if os_name == "Windows":
            raise PermissionError(
                "Failed to create raw socket on Windows: Permission denied. "
                "Please run this script as Administrator. "
                "Note: Windows raw sockets have limitations; consider installing npcap for better packet capture."
            ) from e
        raise PermissionError(f"Failed to create raw socket: {e}. Please run this script with root privileges.") from e
    except socket.error as e:
        raise RuntimeError(f"Socket creation failed: {e}") from e

def parse_packet(packet, os_name):
    if os_name == "Linux" and len(packet) < 34:
        return None
    if os_name == "Windows" and len(packet) < 20:
        return None

    if os_name == "Linux":
        eth_protocol = socket.ntohs(struct.unpack('!H', packet[12:14])[0])
        if eth_protocol != 0x0800:
            return None
        ip_header = packet[14:34]
    else:
        ip_header = packet[:20]

    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    ihl = iph[0] & 0xF
    iph_length = ihl * 4
    
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    
    payload_start = (14 + iph_length) if os_name == "Linux" else iph_length
    payload = packet[payload_start:payload_start + 64]
    payload_hex = binascii.hexlify(payload).decode('utf-8')
    
    return src_ip, dst_ip, protocol, payload_hex

def generate_reports(packet_data):
    df_data = []
    for (src_ip, dst_ip), count in packet_data.items():
        df_data.append({'Visitor IP': src_ip, 'Website IP': dst_ip, 'Packets Sent': count})
    
    df = pd.DataFrame(df_data)
    df.to_csv('report.csv', index=False)
    
    with open('report.txt', 'w') as f:
        f.write("Packet Sniffer Report\n")
        f.write("====================\n\n")
        f.write(f"Total unique connections: {len(packet_data)}\n")
        f.write("Summary of captured packets:\n\n")
        for (src_ip, dst_ip), count in packet_data.items():
            f.write(f"Visitor IP: {src_ip} -> Website IP: {dst_ip}, Packets: {count}\n")

def main():
    try:
        s, os_name = create_socket()
        print(f"Packet sniffer started on {os_name}... (Ctrl+C to stop)")
        
        packet_data = defaultdict(int)
        
        while True:
            packet, _ = s.recvfrom(65535)
            result = parse_packet(packet, os_name)
            
            if result:
                src_ip, dst_ip, protocol, payload = result
                packet_data[(src_ip, dst_ip)] += 1
                print(f"Captured Packet: Src={src_ip}, Dst={dst_ip}, Proto={protocol}, Payload={payload}")
    except KeyboardInterrupt:
        print("\nPacket sniffer stopped.")
        print("Generating reports...")
        generate_reports(packet_data)
        print("Reports generated: report.csv (Excel) and report.txt")
    except (PermissionError, RuntimeError) as e:
        print(f"Error: {e}")
    finally:
        if 's' in locals():
            if os_name == "Windows":
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()

if __name__ == "__main__":
    main()