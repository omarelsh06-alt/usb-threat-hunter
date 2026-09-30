# USB Threat Hunter & Artifact Auditor

A lightweight Digital Forensics and Incident Response (DFIR) triage tool built in Python. Designed to inspect external mass storage devices (USBs, external HDDs) for deceptive malware vectors, persistence scripts, and obfuscation techniques.

## Features

- **Double Extension Detection:** Flags deceptive naming tactics commonly used in phishing and malware delivery (e.g., `document.pdf.exe`).
- **Suspicious Executable & Script Enumeration:** Scans for `.exe`, `.vbs`, `.bat`, `.cmd`, `.ps1`, `.scr`, and `.lnk` files.
- **Legacy Worm Artifact Inspection:** Detects `autorun.inf` files historically utilized in worm replication.
- **Forensic SHA-256 Hashing:** Automatically computes integrity hashes for identified artifacts for IOC matching and triage.
- **Markdown Incident Reporting:** Automatically structures scan findings into a formatted report within the `reports/` directory.

## Usage

1. Run the scanner:
   ```bash
   python usb_hunter.py
