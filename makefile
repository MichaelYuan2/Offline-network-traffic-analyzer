input_file = sample_data/DHCP_Release.txt

test_files = sample_data/DHCP_Release.txt \
             sample_data/dns_test.txt \
             sample_data/dns.txt \
             sample_data/Lab5Hex.txt \
             sample_data/Lab5Hex1A6.txt \

save_results = True
output_folder = results

make file: 
	@echo "Running the program..."
	@if [ "$(save_results)" = "True" ]; then \
		python3 main.py --input_file $(input_file) --output_folder $(output_folder); \
		echo "Results saved in $(output_folder)"; \
	else \
		python3 main.py --input_file $(input_file); \
	fi

make files:
	@echo "Running tests..."
	@for file in $(test_files); do \
		echo "Running test on $$file"; \
		if [ "$(save_results)" = "True" ]; then \
			python3 main.py --input_file $$file --output_folder $(output_folder); \
			echo "Results saved in $(output_folder)"; \
		else \
			python3 main.py --input_file $$file; \
		fi; \
		echo "Test on $$file completed\n"; \
		echo "-----------------------------------\n"; \
	done
