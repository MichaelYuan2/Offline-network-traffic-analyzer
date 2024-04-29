# Offline-network-traffic-analyzer
Course project for CSCI-SHU 308 Computer Networking

# Use makefile to run the program
``` bash
make run
```

# Use python CLI
``` bash
python main.py --input_path <path_to_pcap_file>
```

# Test each layer independently
Go to *Extractor/*, and run the .py file corrresponding to that layer

e.g. to test the Ethernet layer
``` bash
python Ethernet.py
```