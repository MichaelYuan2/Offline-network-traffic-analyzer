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
        self.err_msg = None
    
    def parse_packet(self):
        self.ethernet = Ethernet(self.hexdump)
        ip_hexdump = self.ethernet.get_payload()

        # Check if the packet uses IPv4
        self.ip = IP(ip_hexdump)
        if self.ip.version == 6:
            self.err_msg = "ERROR: IPv6 playload prase is not supported"
        elif self.ip.version == 4:
            if self.ip.protocol == "UDP":
                udp_hexdump = self.ip.get_payload()
                self.udp = UDP(udp_hexdump)
                udp_payload = self.udp.get_payload()

                # Check if the packet uses DNS or DHCP
                try:
                    self.dns = DNS(udp_payload)
                except:
                    self.dns = None
                try :
                    self.dhcp = DHCP(udp_payload)
                except:
                    self.dhcp = None
                if not self.dns and not self.dhcp:
                    self.err_msg = "ERROR: Unknown UDP payload. Only DNS and DHCP are supported."
            else:
                self.err_msg = "ERROR: {} protocol is not supported".format(self.ip.protocol)


    def __str__(self):
        if self.err_msg != None:
            try:
                return f"Ethernet:\n{self.ethernet}\nIP:\n{self.ip}\nUDP:\n{self.udp}\n" +self.err_msg+ "\n"+"Done!"
            except:
                return f"Ethernet:\n{self.ethernet}\nIP:\n{self.ip}\n" +self.err_msg+ "\n"+"Done!"
        
        elif self.dns:
            return f"Ethernet:\n{self.ethernet}\nIP:\n{self.ip}\nUDP:\n{self.udp}\nDNS:\n{self.dns}"+"\n"+"Done!"
        elif self.dhcp: 
            return f"Ethernet:\n{self.ethernet}\nIP:\n{self.ip}\nUDP:\n{self.udp}\nDHCP:\n{self.dhcp}"+"\n" +"Done!"
        return "Unknown packet type"
    
    def get_report(self): 
        self.parse_packet()
        return print(self)
    

def read_hexdump(file_path):
    with open(file_path, 'r') as file:
        hexdump = file.read().replace("\n", "").replace(" ", "")
    return hexdump


if __name__ == '__main__':
    file_path = './sample_data/Processed_dns.txt'
    hexdump = read_hexdump(file_path)
    network_packet = NetworkAnalyzer(hexdump)
    network_packet.get_report()