import argparse
from Network_Analyzer import NetworkAnalyzer
from utils.preprocess import *
import os

def display_frames(frames):
    num_frames = len(frames)
    batch_size = 10
    start_index = 0
    
    while start_index < num_frames:
        end_index = min(start_index + batch_size, num_frames)
        batch_frames = frames[start_index:end_index]
        
        for i, frame in enumerate(batch_frames, start=start_index):
            print(f"Frame {i+1}:")
            network_packet = NetworkAnalyzer(frame)
            print(network_packet.get_report())
        
        if end_index < num_frames:
            input("Press Enter to display the next 10 frames...")
        
        start_index = end_index

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Analyze network packets from a hexdump file.')
    parser.add_argument('--input_file', help='Path to the input file')
    parser.add_argument('--save_results', help='Save the results to a file', default=False, action='store_true')
    parser.add_argument('--output_folder_path', help='Path to the output folder (optional)', default='results')

    # Parse the arguments
    args = parser.parse_args()

    # preprocess the hexdump file using the provided input file path
    frames = read_store(args.input_file)
    display_frames(frames)

    if args.save_results:
        # Save the output to a file
        if not os.path.exists(args.output_folder_path):
            os.makedirs(args.output_folder_path)
        file_name  = "out_" + os.path.basename(args.input_file)
        output_file_path = os.path.join(args.output_folder_path, file_name)
        with open(output_file_path, 'w') as file:
            for i, frame in enumerate(frames):
                file.write(f"Frame {i+1}:\n")
                network_packet = NetworkAnalyzer(frame)
                file.write(network_packet.get_report())
                file.write('\n')

if __name__ == "__main__":
    main()
    
