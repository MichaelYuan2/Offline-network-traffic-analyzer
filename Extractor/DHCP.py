# DHCP

class DHCP():
    def __init__(self, hexdump) -> None:
        self.hexdump = hexdump
        self.opcode_type = {
            1: "BOOTREQUEST",
            2: "BOOTREPLY"
        }
        self.flags_type = {
            0: "Unicast",
            1: "Broadcast"
        }
        self.message_type = {
            1: "DHCP DISCOVER",
            2: "DHCP OFFER",
            3: "DHCP REQUEST",
            4: "DHCP DECLINE",
            5: "DHCP ACK",
            6: "DHCP NAK",
            7: "DHCP RELEASE",
            8: "DHCP INFORM"
        }
        self.option_type = {
            1: "Subnet Mask",
            3: "Router",
            6: "Domain Name Server",
            53: "DHCP Message Type",
            54: "Server Identifier",
            61: "Client Identifier",
            255: "End"
            # more options can be added
        }
        self.options = {}
        self.parse_header()

    def parse_header(self):
        # DHCP header fields and their lengths in bytes
        self.opcode = self.opcode_type.get(int(self.hexdump[0:2]), "Unknown") # 1 for boot request, 2 for boot reply
        self.hardware_type = self.hexdump[2:4] # 1 for ethernet
        self.hardware_address_length = self.hexdump[4:6]
        self.hops = self.hexdump[6:8]
        self.transaction_id = self.hexdump[8:16]
        self.seconds_elapsed = self.hexdump[16:20]
        self.flags = self.hexdump[20:24]
        self.flags = f"{self.flags}" + ' (' + f"{self.flags_type.get(int(self.flags[0], 16) >> 7, 'Unknown')}" + ')'
        self.client_ip = self.hexdump[24:32]
        self.client_ip = '.'.join(str(int(self.client_ip[i:i+2], 16)) for i in range(0, 8, 2))
        self.your_ip = self.hexdump[32:40]
        self.your_ip = '.'.join(str(int(self.your_ip[i:i+2], 16)) for i in range(0, 8, 2))
        self.server_ip = self.hexdump[40:48]
        self.server_ip = '.'.join(str(int(self.server_ip[i:i+2], 16)) for i in range(0, 8, 2))
        self.gateway_ip = self.hexdump[48:56]
        self.gateway_ip = '.'.join(str(int(self.gateway_ip[i:i+2], 16)) for i in range(0, 8, 2))
        self.client_hardware_address = self.hexdump[56:68]
        self.client_hardware_address = ':'.join(self.client_hardware_address[i:i+2] for i in range(0, 12, 2))
        self.client_hardware_padding = self.hexdump[68:88]
        self.server_name = self.hexdump[88:216]
        self.boot_filename = self.hexdump[216:472]
        
        # parse options
        magic_cookie = self.hexdump[472:480]
        if magic_cookie != '63825363':
            # print(magic_cookie)
            raise ValueError('Invalid DHCP magic cookie')
        offset = 480
        parse_options = True
        while parse_options:
            parse_options, offset = self.parse_option(offset)

    def parse_option(self, offset):
        # parse a single option
        option_num = int(self.hexdump[offset:offset+2], 16)
        print(option_num)
        option = self.option_type.get(option_num, 'Unknown')
        if option_num == 255:
            self.options[option] = 'End'
            return False, 0
        elif option_num == 53:
            length = int(self.hexdump[offset+2:offset+4], 16)
            value = self.hexdump[offset+4:offset+4+length*2]
            self.options[option] = self.message_type.get(int(value, 16), 'Unknown')
            offset += 4+length*2
        elif option_num == 54:
            length = int(self.hexdump[offset+2:offset+4], 16)
            value = self.hexdump[offset+4:offset+4+length*2]
            self.options[option] = '.'.join(str(int(value[i:i+2], 16)) for i in range(0, length*2, 2))
            offset += 4+length*2
        elif option_num == 61:
            length = int(self.hexdump[offset+2:offset+4], 16)
            value = self.hexdump[offset+4:offset+4+length*2]
            hardware_type = int(value[0:2], 16)
            self.options[option] = {'Hardware Type': hardware_type}, {'Client Identifier': ':'.join(value[i:i+2] for i in range(2, length*2, 2))}
            offset += 4+length*2
        else:
            length = int(self.hexdump[offset+2:offset+4], 16)
            value = self.hexdump[offset+4:offset+4+length*2]
            self.options[option] = value
            offset += 4+length*2
        return True, offset


    def __str__(self) -> str:
        return f"Opcode: {self.opcode}\n" + \
            f"Hardware Type: {self.hardware_type}\n" + \
            f"Hardware Address Length: {self.hardware_address_length}\n" + \
            f"Hops: {self.hops}\n" + \
            f"Transaction ID: {self.transaction_id}\n" + \
            f"Seconds Elapsed: {self.seconds_elapsed}\n" + \
            f"Flags: {self.flags}\n" + \
            f"Client IP: {self.client_ip}\n" + \
            f"Your IP: {self.your_ip}\n" + \
            f"Server IP: {self.server_ip}\n" + \
            f"Gateway IP: {self.gateway_ip}\n" + \
            f"Client Hardware Address: {self.client_hardware_address}\n" + \
            f"Server Name: {self.server_name}\n" + \
            f"Boot Filename: {self.boot_filename}\n" + \
            f"Options: {self.options}"
            # f"DHCP Message Type: {self.options['DHCP Message Type']}\n" + \

    
if __name__ == '__main__':
    dhcp_message = DHCP('0101060055f6981403000000ac101468000000000000000000000000001cc0e8232100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501073604ac1014d33d0701001cc0e82321ff')
    print(dhcp_message)