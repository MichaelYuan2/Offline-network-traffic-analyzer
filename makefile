input_file = sample_data/DHCP_Release.txt

test_files = sample_data/DHCP_Release.txt \
<<<<<<< HEAD
			sample_data/test1.txt \
=======
			# sample_data/dns_test.txt \
>>>>>>> 097d4384aa47383437cf68d2abe2e647cee7c609
            #  sample_data/dns.txt \
            #  sample_data/Lab5Hex.txt \
			#  sample_data/Lab5Hex1A6.txt \

make run: 
	@echo "Running the program..."
	@python3 main.py --input_file $(input_file)


make test:
	@echo "Running tests..."
	@for file in $(test_files); do \
		echo "Running test on $$file"; \
		python3 main.py --input_file $$file; \
		echo "Test on $$file completed\n"; \
		echo "-----------------------------------\n"; \
	done