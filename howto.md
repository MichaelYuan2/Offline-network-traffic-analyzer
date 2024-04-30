# Offline-network-traffic-analyzer
Course project for CSCI-SHU 308 Computer Networking

# Data File Format
The input file will be a text file containing a hex dump of the traffic captured on the network. The input file may contain multiple Ethernet frames (without Preamble nor FCS fields):

Each line begins with a 2-byte offset followed by 16 bytes in the frame. The offset and the first of these 16 bytes are separated by two spaces. The offset describes the position in the packet of the first byte shown on the corresponding line.
The first line starts with a zero offset (0x0000) followed by two spaces and the first 16 bytes of the frame.

The second line starts with an offset of 0x0010 followed by the next 16 bytes in the frame and so on.

On each line, the 16 bytes in the frame are individually displayed, with spaces separating the bytes from each other. 
Hex digits can be upper or lowercase.
The hexdumps of two consecutive frames are separated by a empty line.
# Use makefile to run the program
The makefile contains the variables and commands to run the program. The following variables are defined in the makefile:
### Variables

- `input_file`: Specifies the one file to be used when running the program. This file is stored in the `sample_data` directory.
- `test_files`: Specifies the multiple files to be used when running the program. These files are stored in the `sample_data` directory.
- `save_results`: Specifies whether to save the output files. The default value is `True`.
- `output_folder`: Specifies the folder where the output files will be saved. The default value is `results`.

### How to use
- `make file`: This command runs the main program using one file specified in `input_file`.
``` bash
make file
```
- `make files`: This command runs the main program using mulitple files specified in `test_files`.
``` bash
make files
```

# Use python CLI
Run the following command to run the program using the python CLI. Replace `<path_to_file>` with the path to the input file. 
``` bash
python main.py --input_path <path_to_file>
```
Optional: If you want to save the output files to a specific folder, replace `<path_to_folder>` with the path to the output folder.
``` bash
python main.py --input_path <path_to_file> --output_folder_path <path_to_folder>
```

# Test each layer independently
Go to *Extractor/*, and run the .py file corrresponding to that layer

e.g. to test the Ethernet layer
``` bash
python Ethernet.py
```