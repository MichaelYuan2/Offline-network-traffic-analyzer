# DNS

class DNS():
    def __init__(self, hexdump) -> None:
        self.hexdump = hexdump
        self.parse_header()

    def parse_header(self):
        # Parse Transaction ID
        self.transaction_id = self.hexdump[0:4]

        # Parse Flags
        # self.flags = self.hexdump[4:8]
        self.flags = self.parse_flags(self.hexdump[4:8])

        # Parse Questions
        self.questions = int(self.hexdump[8:12], 16)

        # Parse Answer RRs
        self.answer_rrs = int(self.hexdump[12:16], 16)

        # Parse Authority RRs
        self.authority_rrs = int(self.hexdump[16:20], 16)

        # Parse Additional RRs
        self.additional_rrs = int(self.hexdump[20:24], 16)

        for i in range(self.questions):
            self.parse_question()

    def parse_flags(self, flag_hexdump):
        flags = int(flag_hexdump, 16)
        qr = flags >> 15
        opcode = (flags & 0x7800) >> 11
        aa = (flags & 0x0400) >> 10
        tc = (flags & 0x0200) >> 9
        rd = (flags & 0x0100) >> 8
        ra = (flags & 0x0080) >> 7
        z = (flags & 0x0070) >> 4
        rcode = flags & 0x000F
        return {
            "QR": qr,
            "Opcode": opcode,
            "AA": aa,
            "TC": tc,
            "RD": rd,
            "RA": ra,
            "Z": z,
            "RCODE": rcode
        }
    
    def parse_question(self):
        # Parse the question section
        pass

    def get_payload(self):
        # Return the payload from the parsed header
        return self.hexdump[24:]
    
if __name__ == '__main__':
    dns_message = DNS('53730100000100000000000006676f6f676c6503636f6d00000f0001')
    print("Transaction ID: 0x{}".format(dns_message.transaction_id))
    print("Flags: {}".format(dns_message.flags))
    print("Questions: {}".format(dns_message.questions))
    print("Answer RRs: {}".format(dns_message.answer_rrs))
    print("Authority RRs: {}".format(dns_message.authority_rrs))
    print("Additional RRs: {}".format(dns_message.additional_rrs))
    print("Payload: {}".format(dns_message.get_payload()))
