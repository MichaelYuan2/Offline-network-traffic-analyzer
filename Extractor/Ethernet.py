class Ethernet:
    def __init__(self, hexdump):
        self.hexdump = hexdump
        self.destination = None
        self.source = None
        self.type = None
        self.parse_header()

    def parse_header(self):
        # Ethernet destination MAC address (6 bytes)
        self.destination = ':'.join(self.hexdump[i:i+2] for i in range(0, 12, 2))

        # Ethernet source MAC address (6 bytes)
        self.source = ':'.join(self.hexdump[i:i+2] for i in range(12, 24, 2))

        # EtherType field (2 bytes)
        self.type = self.hexdump[24:28]

        # Convert hex string to integer
        ethertype_int = int(self.type, 16)

        # Set readable EtherType description
        self.ethertype_description = self.get_ethertype_description(ethertype_int)
        self.type = f"0x{self.type} ({self.ethertype_description})"

    def get_ethertype_description(self, type):
        ethertype_map = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6"
        }
        return ethertype_map.get(type, "Unknown")

    
    def __str__(self) -> str:
        return f"\tDestination: {self.destination}\n"+ \
        f"\tSource: {self.source}\n" + \
        f"\tType: {self.type}"

    def get_payload(self):
    # Return the payload (everything after the Ethernet header)
    # Convert the payload from hexadecimal to decimal
    # Ensure the payload string is not empty to avoid ValueError
        if len(self.hexdump) > 28:
            payload_decimal = self.hexdump[28:]
        else:
            payload_decimal = 0  # Return 0 if there's no payload or it's too short
        return payload_decimal

    
    
def read_hexdump(file_path):
    with open(file_path, 'r') as file:
        hexdump = file.read().replace("\n", "").replace(" ", "")
    return hexdump

# # Reading the hex dump from the file
# file_path = 'Processed_Lab5Hex.txt'
# hexdump = read_hexdump(file_path)

# # Using the Ethernet class to parse the Ethernet header
# ethernet_header = Ethernet(hexdump)
# print(ethernet_header)
def main():
    # Reading the hex dump from the file
    file_path = 'sample_data/Processed_Lab5Hex.txt'
    hexdump = read_hexdump(file_path)
    # Using the Ethernet class to parse the Ethernet header
    ethernet_frame = Ethernet(hexdump)
    # print("Destination MAC:", ethernet_frame.destination)
    # print("Source MAC:", ethernet_frame.source)
    # print("Ethertype (Hex):", hex(ethernet_frame.type))
    # print("Ethertype Description:", ethernet_frame.ethertype_description)
    # print("Payload (Beginning):", ethernet_frame.get_payload())

    print(ethernet_frame)
    
if __name__ == '__main__':
    main()
    

