# offlin network traffic analyzer for UDP packets

class UDP():
    def __init__(self, hexdump):
        self.hexdump = hexdump
        self.parse_header()
    
    def parse_header(self):
        # Parse Source Port
        self.source_port = int(self.hexdump[0:4], 16)
        
        # Parse Destination Port
        self.destination_port = int(self.hexdump[4:8], 16)
        
        # Parse Length
        self.length = int(self.hexdump[8:12], 16)
        
        # Parse Checksum
        # self.checksum = int(self.hexdump[12:16], 16)
        self.checksum = '0x' + str(self.hexdump[12:16])
        
        # Parse Payload
        self.payload = self.hexdump[16:]

    def get_payload(self):
        # Return the payload from the parsed header
        return self.payload
    
    def __str__(self) -> str:
        return f"Source Port: {self.source_port}, Destination Port: {self.destination_port}, Length: {self.length}, Checksum: {self.checksum}"
    

if __name__ == '__main__':
    udp_segment = UDP('ffb400350024659f')
    # print(f"Source Port: {udp_segment.source_port}")
    # print(f"Destination Port: {udp_segment.destination_port}")
    # print(f"Length: {udp_segment.length}")
    # print(f"Checksum: {udp_segment.checksum}")
    # print(f"Payload: {udp_segment.get_payload()}")
    print(udp_segment)