# DHCP

class DHCP():
    def __init__(self, hexdump) -> None:
        self.hexdump = hexdump
        self.message_type = {
            1: "DHCPDISCOVER",
            2: "DHCPOFFER",
            3: "DHCPREQUEST",
            4: "DHCPDECLINE",
            5: "DHCPACK",
            6: "DHCPNAK",
            7: "DHCPRELEASE",
            8: "DHCPINFORM"
        }
        self.option_type = {
            1: "Subnet Mask",
            3: "Router",
            6: "Domain Name Server",
            53: "DHCP Message Type",
            54: "Server Identifier",
            255: "End"
            # more options can be added
        }
        self.options = {}
        self.parse_message()

    def parse_header(self):
        # DHCP header fields and their lengths in bytes
        self.opcode = self.hexdump[0:2] # 1 for boot request, 2 for boot reply
        self.hardware_type = self.hexdump[2:4] # 1 for ethernet
        self.hardware_address_length = self.hexdump[4:6]
        self.hops = self.hexdump[6:8]
        self.transaction_id = self.hexdump[8:16]
        self.seconds_elapsed = self.hexdump[16:20]
        self.flags = self.hexdump[20:24]
        self.client_ip = self.hexdump[24:32]
        self.your_ip = self.hexdump[32:40]
        self.server_ip = self.hexdump[40:48]
        self.gateway_ip = self.hexdump[48:56]
        self.client_hardware_address = self.hexdump[56:72]
        self.server_name = self.hexdump[72:136]
        self.boot_filename = self.hexdump[136:264]
        
        # parse options
        parse_options = True
        while parse_options:
            parse_options = self.parse_option()

    def parse_option(self):
        # parse a single option
        parse_options = True
        option_num = int(self.hexdump[264:266], 16)
        option = self.option_type.get(option_num, 'Unknown')
        if option_num == 'ff':
                parse_options = False
        else:
            length = int(self.hexdump[266:268], 16)
            value = self.hexdump[268:268+length*2]
            self.options[option] = value
            self.hexdump = self.hexdump[268+length*2:]
        return parse_options


    
if __name__ == '__main__':
    dhcp_message = DHCP('01010600872e3800')