# import os
import hashlib
from datetime import datetime
from pathlib import Path

# Suspicious file extensions commonly associated with USB malware vectors
RISKY_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".pif", ".jar", ".lnk"
}

# Deceptive decoy extensions used in double-extension obfuscation attacks
CAMOUFLAGE_EXTS = {".pdf", ".docx", ".xlsx", ".png", ".jpg", ".txt"}


def calculate_sha256(file_path):
    """Computes the SHA-256 cryptographic hash of a given file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError):
        return "Access Denied / Unreadable"


def check_double_extension(filename):
    """Detects double-extension masking techniques (e.g., invoice.pdf.exe)."""
    parts = filename.lower().split(".")
    if len(parts) > 2:
        second_last = "." + parts[-2]
        if second_last in CAMOUFLAGE_EXTS:
            return True
    return False


def scan_target_drive(target_path):
    """Scans the specified storage volume or directory for threat indicators."""
    findings = []
    print(f"[*] Scan Initiated on: {target_path}")
    print("[*] Timestamp: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("-" * 65)

    for root, dirs, files in os.walk(target_path):
        for file in files:
            full_path = os.path.join(root, file)
            path_obj = Path(full_path)
            file_ext = path_obj.suffix.lower()

            threat_types = []

            # 1. Double Extension Camouflage Check
            if check_double_extension(file):
                threat_types.append("Critical: Double Extension Camouflage")

            # 2. Executable / Dangerous Script Check
            if file_ext in RISKY_EXTENSIONS:
                threat_types.append(f"Suspicious Executable/Script ({file_ext})")

            # 3. Legacy Worm / Autorun Detection
            if file.lower() == "autorun.inf":
                threat_types.append("Legacy USB Worm Indicator (autorun.inf)")

            # Record detected artifact
            if threat_types:
                file_hash = calculate_sha256(full_path)
                file_size = os.path.getsize(full_path) if os.path.exists(full_path) else 0

                findings.append({
                    "file_name": file,
                    "path": full_path,
                    "reasons": " | ".join(threat_types),
                    "size_bytes": file_size,
                    "sha256": file_hash
                })
                print(f"[!] DETECTED: {file} -> {' | '.join(threat_types)}")

    return findings


def generate_report(findings, output_folder="reports"):
    """Generates a DFIR-standard Markdown incident response report."""
    os.makedirs(output_folder, exist_ok=True)
    report_name = f"Incident_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_path = os.path.join(output_folder, report_name)

    with open(report_path, "w", encoding="utf-8") as rep:
        rep.write("# USB Incident Response & Threat Hunting Report\n\n")
        rep.write(f"- **Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        rep.write(f"- **Total Flagged Artifacts:** {len(findings)}\n\n")
        rep.write("## Identified Threat Artifacts\n\n")

        if not findings:
            rep.write("No suspicious files, autorun vectors, or disguised extensions detected.\n")
        else:
            rep.write("| File Name | Threat Vector | Size (Bytes) | SHA-256 Hash |\n")
            rep.write("|---|---|---|---|\n")
            for item in findings:
                rep.write(f"| `{item['file_name']}` | {item['reasons']} | {item['size_bytes']} | `{item['sha256']}` |\n")

    print("-" * 65)
    print(f"[+] Incident report generated successfully: {report_path}")


if __name__ == "__main__":
    target_drive = input("Enter target drive or path to scan (e.g., E:\\ or ./test_dir): ").strip()
    if os.path.exists(target_drive):
        detected_threats = scan_target_drive(target_drive)
        generate_report(detected_threats)
    else:
        print("[-] Error: The specified target path does not exist.")
