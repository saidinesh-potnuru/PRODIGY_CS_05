import argparse
from scapy.all import sniff, IP, TCP, UDP, Raw

class PacketSniffer:
    def __init__(self, network_interface=None):
        self.network_interface = network_interface

    def process_packet(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            transport_protocol = self._get_transport_protocol(packet)

            payload_data = self._get_payload(packet)

            self._print_packet_details(ip_layer, transport_protocol, payload_data)

    def _get_transport_protocol(self, packet):
        if packet.haslayer(TCP):
            return 'TCP'
        elif packet.haslayer(UDP):
            return 'UDP'
        else:
            return 'Unknown'

    def _get_payload(self, packet):
        return packet[Raw].load if packet.haslayer(Raw) else None

    def _print_packet_details(self, ip_layer, transport_protocol, payload_data):
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {transport_protocol}")
        if payload_data:
            print(f"Payload: {payload_data}")
        print("\n")

    def start_sniffing(self):
        print("Starting packet sniffing...")
        print("Press Ctrl+C to stop...")
        sniff(iface=self.network_interface, prn=self.process_packet, store=0)

def main():
    parser = argparse.ArgumentParser(description="A simple packet sniffer tool.")
    parser.add_argument('-i', '--interface', help="Network interface to sniff on (e.g., eth0, wlan0)")
    args = parser.parse_args()

    sniffer = PacketSniffer(network_interface=args.interface)
    sniffer.start_sniffing()

if __name__ == "__main__":
    main()
