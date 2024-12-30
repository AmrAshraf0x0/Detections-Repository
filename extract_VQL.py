import os
import re

def extract_vql_from_files(path_to_rules, output_file):
    total_files = 0
    vql_files = 0

    with open(output_file, 'w', encoding='utf-8') as out_f:
        for root, _, files in os.walk(path_to_rules):
            for file in files:
                if file.endswith(".yml"):
                    total_files += 1
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            match = re.search(r"LET\s+ID_\d+\s*=\s*\(.*?\)", content, re.DOTALL)
                            if match:
                                vql_files += 1
                                vql_content = match.group(0)
                                out_f.write(f"{vql_content}\n\n")
                    except Exception as e:
                        out_f.write(f"Failed to read file: {file_path}\n")
                        out_f.write(f"Error: {e}\n\n")

path_to_rules = "C:/Users/amr.ashraf/OneDrive - Hexaprime Technology/Documents/GitHub/Detections-Repository/rules/sigma/rules"
output_file = os.path.join(os.path.dirname(__file__), 'vql_output.txt')
extract_vql_from_files(path_to_rules, output_file)