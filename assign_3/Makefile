# Define Python interpreter
PYTHON = python3

# Define target scripts
CREATE_DB_SCRIPT = create_signature_database.py
DETECT_MALWARE_SCRIPT = malware_detection.py
HASH_VALIDATION_SCRIPT = multi_hash_validation.py
SCAN_AND_QUARANTINE = scan_and_quarantine.py
OBSERVE = observer.py 

# Default target (run all tasks)
task1: create_db detect_malware validate_hashes
task2: scan
test : create_db scan
task3 : observe

# Target to create the signature database
create_db:
	@echo "Creating signature database..."
	$(PYTHON) $(CREATE_DB_SCRIPT)

# Target to detect malware
detect_malware:
	@echo "Running malware detection..."
	$(PYTHON) $(DETECT_MALWARE_SCRIPT)

# Target to validate hashes of sample PDFs
validate_hashes:
	@echo "Validating multi-hashes of PDF files..."
	$(PYTHON) $(HASH_VALIDATION_SCRIPT)

scan:
	@echo "Scanning and quarantine the files"
	$(PYTHON) $(SCAN_AND_QUARANTINE)

observe:
	@echo "Observing test directory"
	$(PYTHON) $(OBSERVE)

# Clean target to remove generated files if needed (optional)
clean:
	@echo "Cleaning up generated files..."
	rm -f malware_signatures.txt

# Help target to list available commands
help:
	@echo "Available commands:"
	@echo "  make all               - Run all tasks"
	@echo "  make create_db         - Create the signature database"
	@echo "  make detect_malware    - Run malware detection"
	@echo "  make validate_hashes   - Validate multi-hashes of PDF files"
	@echo "  make clean             - Clean up generated files"
