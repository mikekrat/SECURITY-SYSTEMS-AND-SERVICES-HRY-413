import hashlib
import glob

def calculate_file_hashes(file_path):
    hash_funcs = {
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256(),
        'sha512': hashlib.sha512()
    }
    with open(file_path, 'rb') as f:
        data = f.read()
        for algo, hash_func in hash_funcs.items():
            hash_func.update(data)
            hash_funcs[algo] = hash_func.hexdigest()
    return hash_funcs

print("starting")
pdf_files = glob.glob("sample_pdfs/*.pdf")  # Make sure sample_pdfs folder exists
print(pdf_files)
hash_results = {}

for pdf_file in pdf_files:
    hash_results[pdf_file] = calculate_file_hashes(pdf_file)

# Pairwise comparisons of hash values
for file1, hashes1 in hash_results.items():
    for file2, hashes2 in hash_results.items():
        if file1 != file2:
            print(f"Comparing {file1} and {file2}:")
            for i in hashes1:
                if hashes1[i] == hashes2[i]:
                    print(f"  {i} hash is identical.")
                else:
                    print(f"  {i} hash is different.")
