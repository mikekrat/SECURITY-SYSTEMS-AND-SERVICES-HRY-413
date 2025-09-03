import os
import hashlib
import shutil
from datetime import datetime

global signatures 

# Load signatures from the signature database
def load_signatures(filename="malware_signatures.txt"):
    global signatures
    signatures = {}
    with open(filename, "r") as file:
        next(file)  # Skip header line
        next(file)  # -----------------
        for line in file:
            md5_hash, sha256_hash,label = line.strip().split(" | ")
            signatures[(md5_hash, sha256_hash)] = label

# Calculate file hashes (MD5, SHA256)
def calculate_hashes(file_path):
    with open (file_path,"r") as file:
        for line in file:
            binary_data = bytes.fromhex(line)
    md5_hash = hashlib.md5(binary_data).hexdigest()
    sha256_hash = hashlib.sha256(binary_data).hexdigest()
    return md5_hash, sha256_hash

# Log detection details to a report
def log_detection(file_path, file_info, status, log_file="detection_report.log"):
    
    with open(log_file, "a") as log:
        log.write(f"{datetime.now()} - {file_path} - {status}\n")
        log.write(f"  Size: {file_info['size']} bytes\n")
        log.write(f"  Type: {file_info['type']}\n")
        log.write(f"  MD5: {file_info['md5']}\n")
        log.write(f"  SHA256: {file_info['sha256']}\n")
        log.write("  ------------------------------------\n")

# Define threat levels
def determine_threat_level(label):
    levels = {
        "malware": "High",
        "non-malware": "Low",
    }
    return levels.get(label, "Medium")

# Quarantine the infected files
def quarantine_file(file_path, quarantine_dir="quarantine"):
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)
    file_name = os.path.basename(file_path)
    quarantine_path = os.path.join(quarantine_dir, file_name)
    shutil.move(file_path, quarantine_path)
    print(f"File {file_name} quarantined to {quarantine_path}")

# Scan directories recursively
def scan_directory(directory):
    global signatures
    

    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            
            # Check if file matches any known malware signature
            status = "Clean"
            

            md5_hash, sha256_hash = calculate_hashes(file_path)
            file_info = {
                "size": os.path.getsize(file_path),
                "type": file_name.split('.')[-1],
                "md5": md5_hash,
                "sha256": sha256_hash
            }

            print(f"md5 {md5_hash} sha256 {sha256_hash}")
            if (md5_hash, sha256_hash) in signatures:
                label = signatures[(md5_hash, sha256_hash)]
                threat_level = determine_threat_level(label)
                print(label)
                status = f"Infected ({threat_level})"
                
                #Quarantine the file if infected
                quarantine_file(file_path)
                
                print(f"ALERT: Detected malware in {file_path}")
                print(f"Threat Level: {threat_level}")
                
            # Log the detection details

            log_detection(file_path, file_info, status)


load_signatures()
with open("detection_report.log", "w") as log:
    pass
# Start scanning the test directory
scan_directory("test_directory")
print("Scanning complete. See detection_report.log for details.")
