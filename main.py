# import everything from Network_Analyzer.py
from Network_Analyzer import NetworkAnalyzer
from utils.preprocess import *

def main():
    input_file_path = "sample_data/dns_3.txt"
    # preprocess the hexdump file
    frames = read_store(input_file_path)
    # Process the frames
    for i, frame in enumerate(frames):
        print(f"Frame {i+1}: ")
        network_packet = NetworkAnalyzer(frame)
        print(network_packet.get_report())

if __name__ == "__main__":
    main()

