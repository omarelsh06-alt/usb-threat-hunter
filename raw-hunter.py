import os
import sys
import math

def calculate_entropy(data):
    # Mathematical function to measure data complexity (Shannon Entropy)
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def read_mbr(drive_number):
    drive_path = f"\\\\.\\PhysicalDrive{drive_number}"
    print(f"[*] Targeting {drive_path}...\n")

    try:
        # Open the physical drive in "rb" (Read Binary) mode
        with open(drive_path, "rb") as disk:
            mbr_data = disk.read(512)

            print("[+] First 512 Bytes (MBR) successfully read!")
            print("-" * 50)

            hex_dump = " ".join(f"{byte:02X}" for byte in mbr_data)
            
            print("First 64 Bytes (Boot Code / Common hiding spot for malware):")
            print(hex_dump[:191])
            print("...\n")
            
            print("Last 2 Bytes (Boot Signature):")
            signature = hex_dump[-5:].strip()
            print(signature)

            if signature == "55 AA":
                print("\n[✔] Standard MBR signature (55 AA) verified.")
            else:
                print("\n[!] WARNING: Non-standard signature! This could indicate a Bootkit.")

            # --- NEW SECTION: ENTROPY ANALYSIS ---
            print("-" * 50)
            print("[*] Performing Shannon Entropy Analysis on Sector 0...")
            entropy_value = calculate_entropy(mbr_data)
            
            print(f"Entropy Level: {entropy_value:.4f} (Scale: 0 - 8)")
            
            if entropy_value > 6.5:
                print("[!] HIGH ENTROPY DETECTED: Highly compressed or encrypted hidden data found. Suspicious!")
            elif entropy_value == 0:
                print("[i] ZERO ENTROPY: Sector is completely empty (All zeros).")
            else:
                print("[✔] NORMAL ENTROPY: Data structure looks typical, no obvious hidden payload.")
            print("-" * 50)

    except PermissionError:
        print("[-] Error: Administrator privileges required!")
        print("Please run your terminal as Administrator.")
    except FileNotFoundError:
        print(f"[-] Error: PhysicalDrive{drive_number} not found. Please check the drive number.")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")

if __name__ == "__main__":
    print("--- RAW DISK FORENSIC HUNTER (v0.2) ---")
    target_disk = input("Enter the physical drive number to read (e.g., 1 or 2 for USB): ").strip()
    
    if target_disk.isdigit():
        read_mbr(int(target_disk))
    else:
        print("Please enter a valid number (e.g., 1)")