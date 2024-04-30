input_file = sample_data/DHCP_Release.txt

test_files = sample_data/DHCP_Release.txt \
			# sample_data/dns_test.txt \
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