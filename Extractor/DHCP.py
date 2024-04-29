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
        self.hardware_types = {
            1: "Ethernet"
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
            2: "Time Offset",
            3: "Router",
            6: "Domain Name Server",
            12: "Host Name",
            15: "Domain Name",
            28: "Broadcast Address",
            33: "Static Route",
            50: "Requested IP Address",
            51: "IP Address Lease Time",
            53: "DHCP Message Type",
            54: "Server Identifier",
            55: "Parameter Request List",
            57: "Maximum DHCP Message Size",
            60: "Vendor Class Identifier",
            61: "Client Identifier",
            66: "TFTP Server Name",
            67: "Bootfile Name",
            82: "Relay Agent Information",
            116: "DHCP Auto-Configuration",
            121: "Classless Static Route",
            150: "TFTP Server IP Address",
            255: "End"
            # more options can be added
        }
        self.options = {}
        self.parse_header()

    def parse_header(self):
        # DHCP header fields and their lengths in bytes
        self.opcode = self.opcode_type.get(int(self.hexdump[0:2]), "Unknown") # 1 for boot request, 2 for boot reply
        self.opcode = f"0x{self.hexdump[0:2]}" + ' (' + f"{self.opcode}"  + ')'
        self.hardware_type = self.hexdump[2:4] # 1 for ethernet
        self.hardware_type = f"0x{self.hardware_type}" + ' (' + f"{self.hardware_types.get(int(self.hardware_type), 'Unknown')}" + ')'
        self.hardware_address_length = self.hexdump[4:6]
        self.hops = self.hexdump[6:8]
        self.hops = f"0x{self.hops}" + ' (' + f"{int(self.hops, 16)}" + ')'
        self.transaction_id = f"0x{self.hexdump[8:16]}"
        self.seconds_elapsed = f"0x{self.hexdump[16:20]}"
        self.flags = self.hexdump[20:24]
        self.flags = f"0x{self.flags}" + ' (' + f"{self.flags_type.get(int(self.flags[0], 16) >> 7, 'Unknown')}" + ')'
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
        # print(option_num)
        # option = self.option_type.get(option_num, f'0x{option_num}' + '(Unknown)')
        option = f"0x{self.hexdump[offset:offset+2]}" + ' (' + f"{self.option_type.get(option_num, 'Unknown option')}" + ')'
        if option_num == 255:
            self.options[option] = ''
            return False, 0
        elif option_num == 53:
            length = int(self.hexdump[offset+2:offset+4], 16)
            value = self.hexdump[offset+4:offset+4+length*2]
            value = f"0x{value}" + ' (' + f"{self.message_type.get(int(value, 16), 'Unknown')}" + ')'
            self.options[option] = value
            offset += 4+length*2
        elif option_num == 54:
            length = int(self.hexdump[offset+2:offset+4], 16)
            value = self.hexdump[offset+4:offset+4+length*2]
            self.options[option] = '.'.join(str(int(value[i:i+2], 16)) for i in range(0, length*2, 2))
            offset += 4+length*2
        elif option_num == 61:
            length = int(self.hexdump[offset+2:offset+4], 16)
            value = self.hexdump[offset+4:offset+4+length*2]
            hardware_type = value[0:2]
            hardware_type = f"0x{hardware_type}" + ' (' + f"{self.hardware_types.get(int(hardware_type), 'Unknown')}" + ')'
            self.options[option] = {'Hardware Type': hardware_type, 'Client Identifier': ':'.join(value[i:i+2] for i in range(2, length*2, 2))}
            offset += 4+length*2
        else:
            length = int(self.hexdump[offset+2:offset+4], 16)
            value = self.hexdump[offset+4:offset+4+length*2]
            self.options[option] = value
            offset += 4+length*2
        return True, offset
    
    def option_str(self):
        # return a string representation of the options
        option_str = '\n'
        for option, value in self.options.items():
            option_str += f"\t\t{option}: {value}\n"
        return option_str


    def __str__(self) -> str:
        return f"\tOpcode: {self.opcode}\n" + \
            f"\tHardware Type: {self.hardware_type}\n" + \
            f"\tHardware Address Length: {self.hardware_address_length}\n" + \
            f"\tHops: {self.hops}\n" + \
            f"\tTransaction ID: {self.transaction_id}\n" + \
            f"\tSeconds Elapsed: {self.seconds_elapsed}\n" + \
            f"\tFlags: {self.flags}\n" + \
            f"\tClient IP: {self.client_ip}\n" + \
            f"\tYour IP: {self.your_ip}\n" + \
            f"\tServer IP: {self.server_ip}\n" + \
            f"\tGateway IP: {self.gateway_ip}\n" + \
            f"\tClient Hardware Address: {self.client_hardware_address}\n" + \
            f"\tServer Name: {self.server_name}\n" + \
            f"\tBoot Filename: {self.boot_filename}\n" + \
            f"\tOptions: {self.option_str()}"
            # f"DHCP Message Type: {self.options['DHCP Message Type']}\n" + \

    
if __name__ == '__main__':
    dhcp_message = DHCP('01010600a27af44c0000000000000000000000000000000000000000001cc0e8232100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501017401013d0701001cc0e823213204ac1014680c094b464943542d4c33313c084d53465420352e30370b010f03062c2e2f1f21f92b2b02dc00ff')
    # dhcp_message = DHCP('0101060055f6981403000000ac101468000000000000000000000000001cc0e8232100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501073604ac1014d33d0701001cc0e82321ff')
    print(dhcp_message)