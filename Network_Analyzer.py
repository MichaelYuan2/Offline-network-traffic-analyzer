# modify the hexdump to remove the offset

# EtherNet Header
# IP Header
# UDP Header
# DNS Header

from Extractor.Ethernet import Ethernet
from Extractor.IP import IP
from Extractor.UDP import UDP
from Extractor.DNS import DNS
from Extractor.DHCP import DHCP

class NetworkAnalyzer():
    ### This class will be used to analyze the network packets
    def __init__(self, hexdump):
        self.hexdump = hexdump
        self.parse_packet()
    
    def parse_packet(self):
        self.ethernet = Ethernet(self.hexdump)
        ip_hexdump = self.ethernet.get_payload()
        print("IP Hexdump: ", ip_hexdump)
        self.ip = IP(ip_hexdump)
        udp_hexdump = self.ip.get_payload()
        print("UDP Hexdump: ", udp_hexdump)
        self.udp = UDP(udp_hexdump)
        udp_payload = self.udp.get_payload()
        print("UDP Payload: ", udp_payload)
        self.dns = DNS(udp_payload)
        try:
            self.dns = DNS(udp_payload)
        except:
            self.dns = None
        try :
            self.dhcp = DHCP(udp_payload)
        except:
            self.dhcp = None
        if not self.dns and not self.dhcp:
            report = "Unknown packet type"

    def __str__(self):
        if self.dns:
            return f"Ethernet: {self.ethernet}\nIP: {self.ip}\nUDP: {self.udp}\nDNS: {self.dns}"
        # if self.dhcp: 
        #     return f"Ethernet: {self.ethernet}\nIP: {self.ip}\nUDP: {self.udp}\nDHCP: {self.dhcp}"
        return "Unknown packet type"
    
    def get_report(self): 
        return str(self)
    

def read_hexdump(file_path):
    with open(file_path, 'r') as file:
        hexdump = file.read().replace("\n", "").replace(" ", "")
    return hexdump


if __name__ == '__main__':
    file_path = 'sample_data/Processed_dns_1.txt'
    hexdump = read_hexdump(file_path)
    network_packet = NetworkAnalyzer(hexdump)
    print(network_packet.get_report())