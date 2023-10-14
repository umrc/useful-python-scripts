import os
import hashlib
import requests
import json

vt_apikey = 'APIKEY'
folder = 'folder'

# Function to calculate the hash of a file
def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to scan a file on VirusTotal
def scan_file_virustotal(file_hash, file_path):

    headers = {
        "accept": "application/json",
        "x-apikey": vt_apikey
    }
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(url, headers=headers)
    try:
        if response.status_code == 200:
            parsed_data = json.loads(response.text)
            last_analysis_stats = parsed_data['data']['attributes']['last_analysis_stats']
            malicious_count = last_analysis_stats['malicious']
            sus_count = last_analysis_stats['suspicious']
            undetected = last_analysis_stats['undetected']
            detected = malicious_count + sus_count
            
            print(f'Detection: {detected}/{detected + undetected}')
        else:
            print(f"File {file_path} is clean/not found.\n")
    except exception as e:
        print(f"Error in API request. {e}\n")

# Main function to recursively iterate through files in a directory
def scan_directory(directory_path):
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_file_hash(file_path)
            print(f"Scanning file: {file_path}")
            scan_file_virustotal(file_hash, file_path)

# Path to the directory you want to scan
folder_path = folder

# Call the function with the folder path
scan_directory(folder_path)
