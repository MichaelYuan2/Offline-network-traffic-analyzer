# import everything from Network_Analyzer.py
from Network_Analyzer import NetworkAnalyzer

def read_store():
    frames = []
    file_path = './sample_data/Processed_Lab5Hex.txt'  
    # Open the file in read mode
    with open(file_path, 'r') as file:
        frames = file.readlines()  # Read all lines and store them in a list
    return frames

def main():
    frames = read_store()
    # Process the frames
    for i, frame in enumerate(frames):
        print(f"Frame {i+1}: {frame}")
        network_packet = NetworkAnalyzer(frame)
        print(network_packet.get_report())

if __name__ == "__main__":
    main()

