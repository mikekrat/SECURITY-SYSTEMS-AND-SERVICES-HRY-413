import hashlib
import os
import random
import string
import shutil
counter = 0

def generate_random_string(main_directory,size=32):
    return os.urandom(size)

def calculate_hashes(data):
    global counter
    md5_hash = hashlib.md5(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()
    create_random_file_in_random_subdir(main_directory,data)
    return md5_hash, sha256_hash

def create_random_file_in_random_subdir(main_dir,data):
    # Traverse directories to a random depth and select a random subdirectory
    global counter
    file_name=f"test{counter}.txt"
    current_dir = main_dir
    while True:
        subdirs = [d for d in os.listdir(current_dir) if os.path.isdir(os.path.join(current_dir, d))]
        
        # Stop if there are no subdirectories, or randomly stop recursion at any level
        if not subdirs or random.choice([True, False]):
            break
        
        # Choose a random subdirectory and go deeper
        current_dir = os.path.join(current_dir, random.choice(subdirs))
    
    # Create and write to the file in the selected directory
    file_path = os.path.join(current_dir, file_name)
    md5_hash = hashlib.md5(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()
    print(md5_hash,sha256_hash)
    with open(file_path, "w") as f:
        f.write(data.hex())
    counter  += 1

def generate_random_directory_structure(base_dir, depth=3, max_subdirs=3):
    if os.path.exists(base_dir):
        shutil.rmtree(base_dir)
    
    os.makedirs(base_dir)
    
    def create_subdirs(current_dir, current_depth):
        """Helper function to create subdirectories recursively."""
        if current_depth >= depth:
            return
        
        # Random number of subdirectories at this level
        num_subdirs = random.randint(1, max_subdirs)
        
        for i in range(num_subdirs):
            # Generate a random subdirectory name
            subdir_name = ''.join(random.choices(string.ascii_letters, k=5))
            subdir_path = os.path.join(current_dir, subdir_name)
            os.makedirs(subdir_path, exist_ok=True)
            
            # Recursively create subdirectories in this subdirectory
            create_subdirs(subdir_path, current_depth + 1)
    
    # Start creating the structure
    create_subdirs(base_dir, 0)

main_directory = "test_directory"
generate_random_directory_structure(main_directory)

# Generate 50 entries
entries = []
for i in range(50):
    label = "malware" if random.choice([True, False]) else "non-malware"
    random_data = generate_random_string(random.randint(10, 100))
    md5_hash, sha256_hash = calculate_hashes(random_data)
    entries.append(f"{md5_hash} | {sha256_hash} | {label}")

# Save to malware_signatures.txt
with open("malware_signatures.txt", "w") as file:
    file.write("MD5 Hash | SHA256 Hash | Malware Type | Infection Date | Severity Level\n")  # Column headers
    file.write("-------------------------------------------------------------------------------------\n")  # Column headers
    file.write("\n".join(entries))

print("Signature database created as 'malware_signatures.txt'.")




