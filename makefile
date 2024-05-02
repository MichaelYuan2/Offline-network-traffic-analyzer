input_file = sample_data/dns_test.txt

input_files = sample_data/DHCP_Release.txt \
			sample_data/dns.txt \
            sample_data/Lab5Hex.txt \
            sample_data/Lab5Hex1A6.txt \
			# sample_data/dns_test.txt \


save_results = False
output_folder = results

make file: 
	@echo "Starting analysis on $(input_file) file..."
	@if [ "$(save_results)" = "True" ]; then \
		python3 main.py --input_file $(input_file) --save_results --output_folder $(output_folder); \
		echo "Results saved in $(output_folder)"; \
	else \
		python3 main.py --input_file $(input_file); \
	fi

make files:
	@echo "Start analysis on multiple files..."
	@for file in $(input_files); do \
		echo "Running test on $$file"; \
		if [ "$(save_results)" = "True" ]; then \
			python3 main.py --input_file $$file --save_results --output_folder $(output_folder); \
			echo "Results saved in $(output_folder)"; \
		else \
			python3 main.py --input_file $$file; \
		fi; \
		echo "Test on $$file completed\n"; \
		echo "-----------------------------------\n"; \
	done
