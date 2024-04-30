input_file = sample_data/DHCP_Release.txt

make run: 
	@echo "Running the program..."
	@python3 main.py --input_file $(input_file)
