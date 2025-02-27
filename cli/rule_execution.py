def execute_rules(log_file):
    """Execute rules on logs."""
    try:
        # Logic for parsing logs and matching with rules
        print(f"Executing rules on log file: {log_file}")
        # Example of processing logs (assuming rules are loaded already)
        with open(log_file, 'r') as log:
            log_lines = log.readlines()
            # Here, process each line with loaded rules
            for line in log_lines:
                print(f"Processing line: {line}")
    except FileNotFoundError as fnfe:
        print(f"Error: {fnfe}")
    except Exception as e:
        print(f"An error occurred: {e}")
