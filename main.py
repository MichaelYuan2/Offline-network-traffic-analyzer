import argparse
from Network_Analyzer import NetworkAnalyzer
from utils.preprocess import *

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Analyze network packets from a hexdump file.')
    parser.add_argument('--input_file', help='Path to the input .pcap file')

    # Parse the arguments
    args = parser.parse_args()

    # preprocess the hexdump file using the provided input file path
    frames = read_store(args.input_file)

    # Process the frames
    for i, frame in enumerate(frames):
        print(f"Frame {i+1}: ")
        network_packet = NetworkAnalyzer(frame)
        print(network_packet.get_report())

if __name__ == "__main__":
    main()
