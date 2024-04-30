# DNS
# Todo - Add more RR types and classes

class DNS():
    def __init__(self, hexdump) -> None:
        self.hexdump = hexdump
        self.question_types = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            32: "NB",
            33: "SRV",
            # Add more as needed
        }

        self.question_classes = {
            1: "IN",
            2: "CS",
            3: "CH",
            4: "HS",
            33: "ANY",
            # Add more as needed
        }
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

        # Parse the question section
        self.parsed_questions = []
        offset = 24
        for _ in range(self.questions):
            question, offset = self.parse_question(offset)
            self.parsed_questions.append(question)

        # Parse Answer RRs
        self.parsed_answer_rrs = []
        for _ in range(self.answer_rrs):
            answer_rr, offset = self.parse_answer_rr(offset)
            self.parsed_answer_rrs.append(answer_rr)

        # Parse Authority RRs
        self.parsed_authority_rrs = []
        # print("Parsing Authority RRs")
        for _ in range(self.authority_rrs):
            authority_rr, offset = self.parse_authority_rr(offset)
            self.parsed_authority_rrs.append(authority_rr)

        # Parse Additional RRs
        self.parsed_additional_rrs = []
        # print("Parsing Additional RRs")
        for _ in range(self.additional_rrs):
            additional_rr, offset = self.parse_additional_rr(offset)
            self.parsed_additional_rrs.append(additional_rr)


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
    
    def parse_domain_name(self, offset):
        domain_name = ""
        while True:
            length_byte = int(self.hexdump[offset:offset + 2], 16)
            if length_byte == 0:
                offset += 2
                break
            # Check if the two most significant bits are set (indicating a pointer)
            if length_byte & 0xc0 == 0xc0:
                # Pointer detected
                pointer_offset = (int(self.hexdump[offset:offset + 4], 16) & 0x3fff) * 2
                # Recursively parse the domain name from the pointer offset
                pointer_domain_name, _ = self.parse_domain_name(pointer_offset)
                # print(pointer_domain_name)
                domain_name += pointer_domain_name + '.'
                # Move the offset past the pointer
                offset += 4
                break
            # If not a pointer, continue parsing the domain name normally
            offset += 2
            domain_name += bytes.fromhex(self.hexdump[offset:offset + (length_byte * 2)]).decode("utf-8") + "."
            offset += length_byte * 2
        return domain_name[:-1], offset
    
    def parse_question(self, offset):
        domain_name, offset = self.parse_domain_name(offset)
        question_type = self.hexdump[offset:offset + 4]
        question_type = f"0x{question_type}" + '(' + f"{self.question_types.get(int(question_type, 16), question_type)}" + ')'
        question_class = self.hexdump[offset + 4:offset + 8]
        question_class = f"0x{question_class}" + '(' + f"{self.question_classes.get(int(question_class, 16), question_class)}" + ')'
        offset += 8
        return {"domain_name": domain_name, "question_type": question_type, "question_class": question_class}, offset

    def parse_answer_rr(self, offset):
        # Parse a single answer RR from the hexdump
        domain_name, offset = self.parse_domain_name(offset)
        rr_type = self.hexdump[offset:offset + 4]
        rr_type = f"0x{rr_type}" + '(' + f"{self.question_types.get(int(rr_type, 16), rr_type)}" + ')'
        rr_class = self.hexdump[offset + 4:offset + 8]
        rr_class = f"0x{rr_class}" + '(' + f"{self.question_classes.get(int(rr_class, 16), rr_class)}" + ')'
        ttl = self.hexdump[offset + 8:offset + 16]
        ttl = f"0x{ttl}" + '(' + f"{int(ttl, 16)}" + ')'
        data_length = self.hexdump[offset + 16:offset + 20]
        data_length_str = f"0x{data_length}" + '(' + f"{int(data_length, 16)}" + ')'
        data_length = int(data_length, 16)
        preference = self.hexdump[offset + 20:offset + 24]
        preference = f"0x{preference}" + '(' + f"{int(preference, 16)}" + ')'
        rr_data, _ = self.parse_domain_name(offset + 24)
        # rr_data = self.hexdump[offset + 24:offset + 24 + (data_length * 2)]
        offset += 20 + (data_length * 2)
        return {"domain_name": domain_name, "rr_type": rr_type, "rr_class": rr_class, "ttl": ttl, "data_length": data_length_str, "preference": preference,  "rr_data": rr_data}, offset

    def parse_authority_rr(self, offset):
        domain_name, offset = self.parse_domain_name(offset)
        rr_type = self.hexdump[offset:offset + 4]
        rr_type = f"0x{rr_type}" + '(' + f"{self.question_types.get(int(rr_type, 16), rr_type)}" + ')'
        rr_class = self.hexdump[offset + 4:offset + 8]
        rr_class = f"0x{rr_class}" + '(' + f"{self.question_classes.get(int(rr_class, 16), rr_class)}" + ')'
        ttl = self.hexdump[offset + 8:offset + 16]
        ttl = f"0x{ttl}" + '(' + f"{int(ttl, 16)}" + ')'
        data_length = self.hexdump[offset + 16:offset + 20]
        data_length_str = f"0x{data_length}" + '(' + f"{int(data_length, 16)}" + ')'
        data_length = int(data_length, 16)
        rr_data, _ = self.parse_domain_name(offset + 20)
        # rr_data = self.hexdump[offset + 20:offset + 20 + (data_length * 2)]
        offset += 20 + (data_length * 2)
        return {"domain_name": domain_name, "rr_type": rr_type, "rr_class": rr_class, "ttl": ttl, "data_length": data_length_str, "rr_data": rr_data}, offset


    def parse_IPv4Address(self, hexdump):
        # Parse an IPv4 address from the hexdump
        address = ".".join([str(int(hexdump[i:i + 2], 16)) for i in range(0, 8, 2)])
        return address
    
    def parse_IPv6Address(self, hexdump):
        # Parse an IPv6 address from the hexdump
        address = ":".join([hexdump[i:i + 4] for i in range(0, 32, 4)])
        return address
    
    def parse_additional_rr(self, offset):
        domain_name, offset = self.parse_domain_name(offset)
        rr_type = self.hexdump[offset:offset + 4]
        rr_type_str = f"0x{rr_type}" + '(' + f"{self.question_types.get(int(rr_type, 16), rr_type)}" + ')'
        rr_type = int(rr_type, 16)
        rr_class = self.hexdump[offset + 4:offset + 8]
        rr_class = f"0x{rr_class}" + '(' + f"{self.question_classes.get(int(rr_class, 16), rr_class)}" + ')'
        ttl = self.hexdump[offset + 8:offset + 16]
        ttl = f"0x{ttl}" + '(' + f"{int(ttl, 16)}" + ')'
        data_length = self.hexdump[offset + 16:offset + 20]
        data_length_str = f"0x{data_length}" + '(' + f"{int(data_length, 16)}" + ')'
        data_length = int(data_length, 16)

        if rr_type == 1:
            rr_data = self.hexdump[offset + 20:offset + 20 + (data_length * 2)]
            rr_data = self.parse_IPv4Address(rr_data)
        elif rr_type == 28:
            rr_data = self.hexdump[offset + 20:offset + 20 + (data_length * 2)]
            rr_data = self.parse_IPv6Address(rr_data)
        else:
            rr_data = self.hexdump[offset + 20:offset + 20 + (data_length * 2)]
        offset += 20 + (data_length * 2)
        return {"domain_name": domain_name, "rr_type": rr_type_str, "rr_class": rr_class, "ttl": ttl, "data_length": data_length_str, "rr_data": rr_data}, offset

    def get_payload(self):
        # Return the payload from the parsed header
        return self.hexdump[24:]
    
    def __str__(self) -> str:
        return f"\tTransaction ID: 0x{self.transaction_id},\n" + \
                f"\tFlags: {self.flags},\n" + \
                f"\tQuestions: {self.questions},\n" + \
                f"\tAnswer RRs: {self.answer_rrs},\n" + \
                f"\tAuthority RRs: {self.authority_rrs},\n" + \
                f"\tAdditional RRs: {self.additional_rrs},\n" + \
                f"\tQuestions: {self.parsed_questions},\n" + \
                f"\tAnswer RRs: {self.parsed_answer_rrs},\n" + \
                f"\tAuthority RRs: {self.parsed_authority_rrs},\n" + \
                f"\tAdditional RRs: {self.parsed_additional_rrs}"



if __name__ == '__main__':
    def print_out(list):
        for i in list:
            print(i)

    # dns_message = DNS('53730100000100000000000006676f6f676c6503636f6d00000f0001')
    dns_message = DNS('53738180000100050004000c06676f6f676c6503636f6d00000f0001c00c000f0001000002580011002804616c7433056173706d78016cc00cc00c000f0001000002580009003204616c7434c02fc00c000f0001000002580009001e04616c7432c02fc00c000f0001000002580009001404616c7431c02fc00c000f0001000002580004000ac02fc00c00020001000110770006036e7333c00cc00c00020001000110770006036e7332c00cc00c00020001000110770006036e7334c00cc00c00020001000110770006036e7331c00cc05c001c00010000012500102a00145040100c1c000000000000001bc02a001c00010000012500102404680040030c00000000000000001bc02f001c00010000012500102a001450400c0c00000000000000001bc047001c00010000012500102404680040080c13000000000000001bc071001c00010000012500102a00145040250c03000000000000001bc0a6001c0001000021b800102001486048020034000000000000000ac0b8001c000100016a2f00102001486048020038000000000000000ac094001c0001000021b800102001486048020036000000000000000ac0ca001c000100016a2f00102001486048020032000000000000000ac05c000100010000012500048efa961bc02a000100010000012500044a7dc81bc02f000100010000012500048efb051b')
    print("Transaction ID: 0x{}".format(dns_message.transaction_id))
    print("Flags: {}".format(dns_message.flags))
    print("Questions: {}".format(dns_message.questions))
    print("Answer RRs: {}".format(dns_message.answer_rrs))
    print("Authority RRs: {}".format(dns_message.authority_rrs))
    print("Additional RRs: {}".format(dns_message.additional_rrs))
    print("Questions:")
    print_out(dns_message.parsed_questions)
    print("Answer RRs:")
    print_out(dns_message.parsed_answer_rrs)
    print("Authority RRs:")
    print_out(dns_message.parsed_authority_rrs)
    print("Additional RRs:")
    print_out(dns_message.parsed_additional_rrs)
    # print("Payload: {}".format(dns_message.get_payload()))
