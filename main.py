import argparse
from Network_Analyzer import NetworkAnalyzer
from utils.preprocess import *

def display_frames(frames):
    num_frames = len(frames)
    batch_size = 5
    start_index = 0
    
    while start_index < num_frames:
        end_index = min(start_index + batch_size, num_frames)
        batch_frames = frames[start_index:end_index]
        
        for i, frame in enumerate(batch_frames, start=start_index):
            print(f"Frame {i+1}:")
            network_packet = NetworkAnalyzer(frame)
            print(network_packet.get_report())
        
        if end_index < num_frames:
            input("Press Enter to display the next 5 frames...")
        
        start_index = end_index

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Analyze network packets from a hexdump file.')
    parser.add_argument('--input_file', help='Path to the input .pcap file')

    # Parse the arguments
    args = parser.parse_args()

    # preprocess the hexdump file using the provided input file path
    frames = read_store(args.input_file)

    # Process the frames
    # for i, frame in enumerate(frames):
    #     print(f"Frame {i+1}: ")
    #     network_packet = NetworkAnalyzer(frame)
    #     print(network_packet.get_report())
    display_frames(frames)

if __name__ == "__main__":
    main()
