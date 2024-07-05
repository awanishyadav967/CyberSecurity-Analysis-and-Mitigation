import os
import hashlib
import streamlit as st

# A dictionary of known ransomware file hashes (for demonstration purposes)
KNOWN_RANSOMWARE_HASHES = {

    "c5d2a4d0b7d00a3afbb08068b14217a7034c4b62a2525f4f7377d09d2335c5c5": "WannaCry",
    "6a45d52a6dd2e6b9ad08b013dd320823e6a8055fba6edb4d5bc2b57105dbaf7e": "NotPetya",
    "1c7b8b1a6a54ab5e6b5a7f706f4b8f8cbbd5c2b5a2b2f4b2b5a5b5c5c5c5c5c5": "Cerber"
}

# Function to compute SHA-256 hash of a file
def compute_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        st.error(f"Error computing hash for {file_path}: {str(e)}")
        return None

# Function to scan a directory for ransomware
def scan_directory_for_ransomware(directory):
    results = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = compute_file_hash(file_path)
            if file_hash and file_hash in KNOWN_RANSOMWARE_HASHES:
                results.append((file_path, KNOWN_RANSOMWARE_HASHES[file_hash]))
    return results

def ransomware_analysis_ui():
    st.header("Ransomware Analysis and Mitigation")

    st.sidebar.header("Ransomware Scan Settings")

    # Input field for directory to scan
    directory_to_scan = st.sidebar.text_input("Directory to Scan", "")

    if st.sidebar.button("Start Ransomware Scan"):
        if directory_to_scan and os.path.isdir(directory_to_scan):
            st.write(f"Scanning directory: {directory_to_scan}...")
            scan_results = scan_directory_for_ransomware(directory_to_scan)
            if scan_results:
                st.error("Potential Ransomware Found:")
                for file_path, ransomware_name in scan_results:
                    st.write(f"File: {file_path}, Ransomware: {ransomware_name}")
            else:
                st.success("No known ransomware files found.")
        else:
            st.error("Please enter a valid directory path.")
