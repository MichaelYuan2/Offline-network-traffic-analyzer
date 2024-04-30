class IP:
    def __init__(self, hexdump):
        self.hexdump = hexdump
        self.parse_header()

    def parse_options(self, options):
        index = 0
        options_hex = bytes.fromhex(options)
        options = []
        while index < len(options_hex):
            option = {}
            option_type = options_hex[index]
            option['type'] = f"{option_type:#04x}"

            if option_type == 0x00:
                option['description'] = "EOL (End of List)"
                option['length'] = 1
                options.append(option)
                break  # No more options after EOL
            elif option_type == 0x01:
                option['description'] = "NOP (No Operation)"
                option['length'] = 1
                options.append(option)
                index += 1  # NOP option is 1 byte
            else:
                if index + 1 < len(options_hex):
                    length = options_hex[index + 1]
                    option['length'] = length
                    if length + index > len(options_hex):
                        raise ValueError("Invalid option length")
                    if option_type == 0x07:
                        option_pointer = options_hex[index + 2]
                        option['pointer'] = option_pointer
                        option_content = options_hex[index + 3:index + length]
                        option['content'] = option_content.hex()
                    else:
                        option_content = options_hex[index + 2:index + length]
                        option['content'] = option_content.hex()

                    if option_type == 0x83:
                        option['description'] = "Loose Routing"
                    elif option_type == 0x89:
                        option['description'] = "Strict Routing"
                    elif option_type == 0x07:
                        option['description'] = "Record Route"
                    elif option_type == 0x44:
                        option['description'] = "Timestamp"
                    else:
                        option['description'] = f"Unknown Option ({option_type:#04x})"
                    options.append(option)
                    index += length  # Move the index by the length of the option
                else:
                    raise ValueError("Invalid option length")
        return options


    def parse_header(self):
        # Parse version and IHL
        byte1 = int(self.hexdump[0:2], 16)
        
        self.version = byte1 >> 4
        if self.version != 4 and self.version != 6:
            raise ValueError('Invalid IP version')
        if self.version == 4:
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
            # convert protocol number to protocol name use dictionary
            protocol_dict = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            self.protocol_str = f'0x{self.protocol}' + ' (' + protocol_dict.get(int(self.protocol, 16), 'Unknown') + ')'
            self.protocol = protocol_dict.get(int(self.protocol, 16), 'Unknown')

            # Parse Header Checksum
            self.checksum = int(self.hexdump[20:24], 16)

            # Parse Source Address
            self.source_address = '.'.join(str(int(self.hexdump[i:i+2], 16)) for i in range(24, 32, 2))

            # Parse Destination Address
            self.destination_address = '.'.join(str(int(self.hexdump[i:i+2], 16)) for i in range(32, 40, 2))

            # Parse Options
            if self.ihl > 5:
                options_hexdump = self.hexdump[40:self.ihl*8]
                self.options = self.parse_options(options_hexdump)
            else:
                self.options = None

            # Parse Payload Length
            self.payload_length = self.total_length - self.ihl*4

        elif self.version == 6:
                # Parse IPv6 header
                self.ihl = 40
                # Assuming the next header field starts at position 20
                self.next_header = int(self.hexdump[20:22], 16)
                self.hop_limit = int(self.hexdump[22:24], 16)
                self.source_address = ":".join(self.hexdump[i:i+4] for i in range(24, 40, 4))
                self.destination_address = ":".join(self.hexdump[i:i+4] for i in range(40, 56, 4))

    def get_payload(self):
        # Return the payload from the parsed header
        return self.hexdump[self.ihl*8:]

    def __str__(self) -> str:
        if self.version == 6:
            return f"\tVersion: {self.version}\n" + \
                f"\tNext Header: {self.next_header}\n" + \
                f"\tHop Limit: {self.hop_limit}\n" + \
                f"\tSource Address: {self.source_address}\n" + \
                f"\tDestination Address: {self.destination_address}\n"
        else:
            if self.options:
                options_str = "\tOptions:\n"
                for index, option in enumerate(self.options, start=1):
                    options_str += f"\tOption {index}:\n" + \
                                   f"\t\tLength: {option['length']}\n" + \
                                   f"\t\tDescription: {option['description']}\n" + \
                                   (f"\t\tPointer: {option['pointer']}\n" if 'pointer' in option else "") + \
                                   (f"\t\tContent: {option['content']}\n" if 'content' in option else "")
            else:
                options_str = ""
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
                f"\tProtocol: {self.protocol_str}\n" + \
                f"\tChecksum: {self.checksum}\n" + \
                f"\tSource Address: {self.source_address}\n" + \
                f"\tDestination Address: {self.destination_address}\n" + \
                options_str + \
                f"\tPayload Length: {self.payload_length}\n"
        
    
# test it
if __name__ == '__main__':
    ip_header = IP('4f00007ccbc90000ff01b97f84e33d05c0219f060727040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800a2562f00000029368c410003862b08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637')
    print(ip_header)