Statix – Static Malware Analysis Tool

Statix is a  Python-based static analysis tool designed for security researchers and malware analysts. It helps in quickly gathering insights from binary files by extracting hashes, strings, entropy, suspicious imports and functions . 

Features

File Hashing: Computes MD5,  and SHA256 for quick file fingerprinting.

String Extraction: Extracts ASCII, UTF-16LE/BE, and raw blob data.

Suspicious Indicators: Detects potential malware behavior (imports, registry keys, URLs, IPs).

Entropy Analysis: Calculates overall and sliding window entropy for packed/encrypted sections.

Cross-Platform Support: Works on Windows, Linux, and macOS binaries.

Optional Radare2 Integration: Extract function information for advanced disassembly.

- ![MOF Output Demo](https://github.com/katifsec/statix/icon.png)


-----------------------------------------------------------------------------

Installation

Clone the repository:

git clone https://github.com/katifsec/statix.git
cd statix

-----------------------------------------------------------------------------
Install required Python libraries:

pip install -r requirements.txt


(Optional) Install Radare2 if you want to use --use-r2:

sudo apt install radare2   # Linux
-----------------------------------------------------------------------------
Usage
python statix.py [binary_file] [options]

Example:

python statix.py malware_sample.exe --use-r2 --html report.html

-----------------------------------------------------------------------------

Positional arguments:

binary : Path to the binary file (.exe, .dll, .elf, .so)

Optional arguments:

Option	Description
--use-r2	Use Radare2 for function extraction (requires r2 installed)
--r2-fast	Use faster Radare2 analysis (af) instead of full analysis (aa)
--no-disasm	Skip Capstone disassembly heuristics
--json FILE	Save analysis report as JSON




