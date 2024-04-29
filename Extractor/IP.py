class IPv4:
    def __init__(self, hexdump):
        self.hexdump = hexdump
        self.protocol_type = {
            1: 'ICMP',
            2: 'IGMP',
            6: 'TCP',
            17: 'UDP',
            41: 'IPv6',
            89: 'OSPF',
            132: 'SCTP'
        }
        self.parse_header()

    def parse_header(self):
        # Parse version and IHL
        byte1 = int(self.hexdump[0:2], 16)
        
        self.version = byte1 >> 4
        if self.version != 4 and self.version != 6:
            raise ValueError('Invalid IP version')
        
        self.ihl = byte1 & 0x0F

        # Parse Type of Service
        self.tos = int(self.hexdump[2:4], 16)

        # Parse Total Length
        self.total_length = int(self.hexdump[4:8], 16)

        # Parse Identification
        self.identification = int(self.hexdump[8:12], 16)

        # Parse Flags and Fragment Offset
        flags_and_offset = int(self.hexdump[12:16], 16)
        flags = flags_and_offset >> 13
        self.DF = (flags & 0x2) >> 1
        self.MF = flags & 0x1
        self.fragment_offset = flags_and_offset & 0x1FFF

        # Parse Time to Live
        self.ttl = int(self.hexdump[16:18], 16)

        # Parse Protocol
        self.protocol = self.hexdump[18:20]
        self.protocol = f"0x{self.protocol}" + ' (' + f"{self.protocol_type.get(int(self.protocol, 16), 'Unknown Protocol')}" + ')'

        # Parse Header Checksum
        self.checksum = int(self.hexdump[20:24], 16)

        # Parse Source Address
        self.source_address = '.'.join(str(int(self.hexdump[i:i+2], 16)) for i in range(24, 32, 2))

        # Parse Destination Address
        self.destination_address = '.'.join(str(int(self.hexdump[i:i+2], 16)) for i in range(32, 40, 2))

        # Parse Options
        self.options = self.hexdump[40:self.ihl*8]

        # Parse Payload Length
        self.payload_length = self.total_length - self.ihl*4
        
    def get_payload(self):
        # Return the payload from the parsed header
        return self.hexdump[self.ihl*8:]

    def __str__(self) -> str:
        return f"\tVersion: {self.version}\n" + \
            f"\tIHL: {self.ihl}\n" + \
            f"\tTOS: {self.tos}\n" + \
            f"\tTotal Length: {self.total_length}\n" + \
            f"\tVersion: {self.version}\n" + \
            f"\tIdentification: {self.identification}\n" + \
            f"\tDF: {self.DF}\n" + \
            f"\tMF: {self.MF}\n" + \
            f"\tFragment Offset: {self.fragment_offset}\n" + \
            f"\tTTL: {self.ttl}\n" + \
            f"\tProtocol: {self.protocol}\n" + \
            f"\tChecksum: {self.checksum}\n" + \
            f"\tSource Address: {self.source_address}\n" + \
            f"\tDestination Address: {self.destination_address}\n" + \
            f"\tOptions: {self.options}\n" + \
            f"\tPayload Length: {self.payload_length}\n"    
    
# test it
if __name__ == '__main__':
    ip_header = IPv4('45000028000040004006b8420acc023e00108077f50c')
    # print(ip_header.version)
    # print(ip_header.ihl)
    # print(ip_header.tos)
    # print(ip_header.total_length)
    # print(ip_header.identification)
    # print(ip_header.DF)
    # print(ip_header.MF)
    # print(ip_header.fragment_offset)
    # print(ip_header.ttl)
    # print(ip_header.protocol)
    # print(ip_header.checksum)
    # print(ip_header.source_address)
    # print(ip_header.destination_address)
    # print(ip_header.get_payload())
    print(ip_header)