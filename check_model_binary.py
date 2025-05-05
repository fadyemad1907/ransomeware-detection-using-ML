import os

def read_file_in_chunks(file_path, chunk_size=1024):
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            print(chunk[:100])  # Print first 100 bytes of each chunk

try:
    print(f"File size: {os.path.getsize('ransomware_detector_20250417_074204.joblib')} bytes")
    print("\nFile contents (first 1000 bytes):")
    read_file_in_chunks('ransomware_detector_20250417_074204.joblib')
except Exception as e:
    print(f"Error: {str(e)}") 