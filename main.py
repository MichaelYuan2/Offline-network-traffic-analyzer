# import everything from Network_Analyzer.py
from Network_Analyzer import NetworkAnalyzer
from utils.preprocess import *

def main():
    # preprocess the hexdump file
    frames = read_store()
    # Process the frames
    for i, frame in enumerate(frames):
        print(f"Frame {i+1}: {frame}")
        network_packet = NetworkAnalyzer(frame)
        print(network_packet.get_report())

if __name__ == "__main__":
    main()

