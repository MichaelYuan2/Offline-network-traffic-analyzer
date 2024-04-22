# DHCP

class DHCP():
    def __init__(self, hexdump) -> None:
        self.hexdump = hexdump
        self.parse_header()

    def parse_header(self):
        # DHCP header fields and their lengths in bytes
        header_fields = {
            "opcode": 1,
            "hardware_type": 1,
            "hardware_address_length": 1,
            "hops": 1,
            "transaction_id": 4,
            "seconds_elapsed": 2,
            "flags": 2,
            "client_ip": 4,
            "your_ip": 4,
            "server_ip": 4,
            "gateway_ip": 4,
            "client_hardware_address": 16,
            "server_name": 64,
            "boot_filename": 128,
            # Additional fields can be added as needed
        }

        # Parse header fields
        offset = 0
        for field, length in header_fields.items():
            value = self.hexdump[offset:offset + (length * 2)]
            # Convert hex string to integer if needed
            if length > 1:
                value = int(value, 16)
            print(f"{field}: {value}")
            offset += length * 2

if __name__ == '__main__':
    dhcp_message = DHCP('01010600872e3800')