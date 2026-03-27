import os
import json
import traceback


# Define function to process log files
def extractor_entity_sequences(new_malicious_entities,logs):
    output_results=[]
    for line in logs:
        if new_malicious_entities.lower() in line.lower().strip():
            output_results.append(line)
    return output_results




def process_log_files(log_dir):
    # Iterate through all files in the folder
    for log_filename in os.listdir(log_dir):
        log_file_path = os.path.join(log_dir, log_filename)

        # Only process log files (assuming .txt format)
        if log_filename.endswith(".txt"):
            with open(log_file_path, 'r', encoding='utf-8') as log_file:
                # Read first line entity name array
                first_line = log_file.readline().strip()
                malicious_entities = []
                data = first_line.strip('[]').split(',')
                malicious_entities=data

                # Set output file path, filename consistent with original file
                output_file_path = os.path.join(log_dir+'\output', f"filtered_{log_filename}")
                if not os.path.exists(output_file_path):
                    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

                # Open output file for writing
                with open(output_file_path, 'w', encoding='utf-8') as output:
                    output.write(','.join(malicious_entities) + '\n')
                    for line in log_file:
                        # Check if line contains malicious entity names
                        if any(entity.lower() in line.lower().strip() for entity in malicious_entities):
                            # If line contains malicious entity, save the line
                            output.write(line)

            print(f"Processing completed, results saved to: {output_file_path}")




def main():
    # Set log folder path
    log_dir = "data/logs/P1-P2/"  # Modify to your log folder path

    # Call processing function
    process_log_files(log_dir)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(traceback.format_exc())
        print(f"Error occurred: {e}")
