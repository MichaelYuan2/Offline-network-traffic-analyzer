# process the hexdump file
def process_hexdump(input_file_path, output_file_path):
    with open(input_file_path, 'r') as infile, open(output_file_path, 'w') as outfile:
        processed_lines = []
        for line in infile:
            if line == "\n":
                processed_lines.append("\n")
            else:
                processed_lines.append(line[6:54].replace(' ', '').strip())
        outfile.write(''.join(processed_lines))

def read_store(input_file_path):
    output_file_path = "./sample_data/processed_{}.txt".format(input_file_path.split("/")[-1].split(".")[0])
    process_hexdump(input_file_path, output_file_path)
    frames = []
    # Open the file in read mode
    with open(output_file_path, 'r') as file:
        frames = file.readlines()  # Read all lines and store them in a list
    return frames

def decode_ethernet_frame(frame_bytes):
    destination_mac = ':'.join(format(byte, '02x') for byte in frame_bytes[0:6])
    source_mac = ':'.join(format(byte, '02x') for byte in frame_bytes[6:12])
    ethertype = frame_bytes[12:14].hex()
    payload = frame_bytes[14:]
    return {
        "Destination MAC": destination_mac,
        "Source MAC": source_mac,
        "Ethertype": ethertype,
        "Payload": payload
    }

def decode_ip_packet(packet_bytes):
    version = packet_bytes[0] >> 4
    ihl = (packet_bytes[0] & 15) * 4
    total_length = int.from_bytes(packet_bytes[2:4], byteorder='big')
    protocol = packet_bytes[9]
    source_ip = '.'.join(str(byte) for byte in packet_bytes[12:16])
    destination_ip = '.'.join(str(byte) for byte in packet_bytes[16:20])
    payload = packet_bytes[ihl:total_length]
    return {
        "Version": version,
        "IHL": ihl,
        "Total Length": total_length,
        "Protocol": protocol,
        "Source IP": source_ip,
        "Destination IP": destination_ip,
        "Payload": payload
    }

def decode_udp_segment(segment_bytes):
    source_port = int.from_bytes(segment_bytes[0:2], byteorder='big')
    destination_port = int.from_bytes(segment_bytes[2:4], byteorder='big')
    length = int.from_bytes(segment_bytes[4:6], byteorder='big')
    payload = segment_bytes[8:length]
    return {
        "Source Port": source_port,
        "Destination Port": destination_port,
        "Length": length,
        "Payload": payload
    }

def decode_dns_message(message_bytes):
    transaction_id = message_bytes[0:2].hex()
    flags = message_bytes[2:4].hex()
    questions = int.from_bytes(message_bytes[4:6], byteorder='big')
    answer_rrs = int.from_bytes(message_bytes[6:8], byteorder='big')
    authority_rrs = int.from_bytes(message_bytes[8:10], byteorder='big')
    additional_rrs = int.from_bytes(message_bytes[10:12], byteorder='big')
    # This is a simplified view; actual DNS decoding would need to parse the question and answer sections.
    return {
        "Transaction ID": transaction_id,
        "Flags": flags,
        "Questions": questions,
        "Answer RRs": answer_rrs,
        "Authority RRs": authority_rrs,
        "Additional RRs": additional_rrs
    }

def decode_dhcp_message(message_bytes):
    op = message_bytes[0]
    htype = message_bytes[1]
    hlen = message_bytes[2]
    hops = message_bytes[3]
    xid = message_bytes[4:8].hex()
    # Simplified; you'd need to parse options starting at byte 240.
    return {
        "Operation": op,
        "Hardware Type": htype,
        "Hardware Address Length": hlen,
        "Hops": hops,
        "Transaction ID": xid
    }
