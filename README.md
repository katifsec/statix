Statix – Static Malware Analysis Tool

Statix is a  Python-based static analysis tool designed for security researchers and malware analysts. It helps in quickly gathering insights from binary files by extracting hashes, strings, entropy, suspicious imports and functions . 

Features <--

File Hashing: Computes MD5,  and SHA256 for quick file fingerprinting.

String Extraction: Extracts ASCII, UTF-16LE/BE, and raw blob data.

Suspicious Indicators: Detects potential malware behavior (imports, registry keys, URLs, IPs).

Entropy Analysis: Calculates overall and sliding window entropy for packed/encrypted sections.

Cross-Platform Support: Works on Windows, Linux, and macOS binaries.

Optional Radare2 Integration: Extract function information for advanced disassembly.

-----------------------------------------------------------------------------

Installation <--

Clone the repository:

git clone https://github.com/yourusername/statix.git
cd statix


Install required Python libraries:

pip install -r requirements.txt


(Optional) Install Radare2 if you want to use --use-r2:

sudo apt install radare2   # Linux
-----------------------------------------------------------------------------
Usage  <--

python statix.py [binary_file] [options]

Example:

python statix.py malware_sample.exe --use-r2 --html report.html

-----------------------------------------------------------------------------




