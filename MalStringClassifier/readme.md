MalStringClassifier

Author: Abhijit Mohanta
Author of the book "Malware Analysis and Detection Engineering"

📖 Description

MalStringClassifier is a Windows-based tool designed to extract strings from binary files and classify them based on their significance. The tool supports both ASCII and Unicode string extraction and generates a CSV report mapping each extracted string to its relevance (such as Anti-VM, C2 communication, scripting engines, URLs, registry usage, etc.).

This tool is particularly useful for malware analysts who want to quickly identify the role of strings inside a binary. For example, whether a string belongs to virtualization detection (VBOX), script execution (powershell), or C2 communication (http:).

By highlighting the significance of each string, the tool helps:

Prioritize strings during malware reverse engineering.

Select the most meaningful strings for writing YARA or other detection rules.

Speed up triage of unknown binaries.

🚀 Features

Drag-and-drop UI for analyzing binary files.

Extracts both ASCII and Unicode strings.

Generates an output CSV named <input_file>_strings.csv.

Each string is mapped to its significance using a configurable dictionary.

Displays tool name (MalStringClassifier) and author credits in the UI.

📂 Output Example

If the tool processes sample.bin, it will generate:
