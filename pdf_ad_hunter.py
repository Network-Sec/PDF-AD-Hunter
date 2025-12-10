#!/usr/bin/env python3

import sys
import os
import re
import pikepdf
from pikepdf import Pdf, Dictionary

# --- CONFIGURATION & COLORS ---
MIN_PATH_LEN = 5
# Only accept strings where >90% of chars are standard ASCII (removes \ÄG·säj noise)
PRINTABLE_THRESHOLD = 0.9 

C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"
C_RESET = "\033[0m"
C_BOLD = "\033[1m"

def print_banner():
    print(f"{C_CYAN}")
    print(r"""
    ____  ____  _____       _    ____   
   |  _ \|  _ \|  ___|     / \  |  _ \  
   | |_) | | | | |_ _____ / _ \ | | | | 
   |  __/| |_| |  _|_____/ ___ \| |_| | 
   |_|   |____/|_|      /_/   \_\____/  
           INTERNAL INFRASTRUCTURE HUNTER v5.0
    """)
    print(f"{C_RESET}")

def is_garbage(s):
    """
    Returns True if the string looks like binary garbage (noise).
    Checks the ratio of standard printable characters vs high-bit garbage.
    """
    if not s: return True
    # Allow standard letters, numbers, common path symbols
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\\/:._- ()[]<>")
    count = sum(1 for c in s if c in allowed)
    ratio = count / len(s)
    
    # If less than 90% of the string is normal text, it's likely a binary blob
    if ratio < PRINTABLE_THRESHOLD:
        return True
    return False

def clean_string(s):
    """
    Decodes bytes to string, removes null bytes, trims whitespace.
    """
    if isinstance(s, bytes):
        try:
            s = s.decode('utf-8', errors='ignore')
        except:
            return ""
    return str(s).strip().replace('\x00', '')

def extract_raw_xmp(content):
    """
    Simulates 'grep -a'. Finds the raw XMP XML block and parses specific fields.
    """
    results = []
    
    # Regex to capture the whole x:xmpmeta block (non-greedy)
    # We use DOTALL so . matches newlines
    xmp_blocks = re.findall(rb'(<x:xmpmeta.*?</x:xmpmeta>)', content, re.DOTALL)
    
    for block in xmp_blocks:
        try:
            block_str = block.decode('utf-8', errors='ignore')
            
            # 1. Extract Creator Tool (often leaks OS version like 'Macintosh')
            creators = re.findall(r'<xmp:CreatorTool>(.*?)</xmp:CreatorTool>', block_str)
            for c in creators:
                results.append((f"{C_YELLOW}[XML] Creator Tool{C_RESET}", c))

            # 2. Extract Instance/Doc IDs (Good for correlation)
            # ids = re.findall(r'InstanceID>(.*?)</', block_str)
            # if ids: results.append((f"{C_RESET}[XML] Instance ID", ids[0]))

            # 3. Extract History (The Gold Mine)
            # We look for the stEvt:parameters or changed or saved actions
            history_items = re.findall(r'<stEvt:parameters>(.*?)</stEvt:parameters>', block_str)
            for h in history_items:
                results.append((f"{C_GREEN}[XML] History Log{C_RESET}", h))
            
            # 4. Extract any loose paths inside XML values
            # Matches: >\\Server\Share< or ="\\Server\Share"
            xml_paths = re.findall(r'[:=>"\'>\s](\\\\[a-zA-Z0-9._$-]+\\[a-zA-Z0-9._$-\\]+)', block_str)
            for p in xml_paths:
                if not is_garbage(p):
                    results.append((f"{C_RED}[XML] UNC Path{C_RESET}", p))
                    
        except Exception as e:
            pass
            
    return results

def analyze_file(filepath):
    filename = os.path.basename(filepath)
    print(f"{C_BOLD}[*] Target: {filename}{C_RESET}")
    
    findings = []
    
    # --- STEP 1: RAW BINARY ANALYSIS (The "Grep" Layer) ---
    try:
        with open(filepath, 'rb') as f:
            raw_content = f.read()
            
        # A. Run the XMP Extractor
        xmp_findings = extract_raw_xmp(raw_content)
        findings.extend(xmp_findings)
        
        # B. Raw Regex for UNC Paths (Strict Mode)
        # Looking for \\Server\Share pattern. 
        # Must have at least one backslash inside.
        unc_pattern = re.compile(rb'\\\\+[a-zA-Z0-9._$-]+\\[a-zA-Z0-9._$-\\]+')
        
        matches = unc_pattern.findall(raw_content)
        for m in matches:
            decoded = clean_string(m)
            if not is_garbage(decoded) and len(decoded) > MIN_PATH_LEN:
                findings.append((f"{C_RED}[RAW] UNC Path{C_RESET}", decoded))
                
        # C. Raw Regex for Local Paths (C:\...)
        # drive_pattern = re.compile(rb'[a-zA-Z]:\\[a-zA-Z0-9._$-\\]+')
        # matches_drive = drive_pattern.findall(raw_content)
        # for m in matches_drive:
        #     decoded = clean_string(m)
        #     if not is_garbage(decoded):
        #         findings.append((f"{C_RED}[RAW] Local Path{C_RESET}", decoded))

    except Exception as e:
        print(f"    {C_RED}[!] Error reading file: {e}{C_RESET}")
        return

    # --- STEP 2: OBJECT ANALYSIS (The "Structure" Layer) ---
    # Pikepdf is good for uncompressing streams that grep can't see
    try:
        pdf = Pdf.open(filepath, allow_overwriting_input=True)
        
        # A. Metadata Dictionary
        meta = pdf.docinfo
        if meta:
            for k, v in meta.items():
                s_val = clean_string(v)
                # Check if metadata value looks like a path or has AD info
                if "\\\\" in s_val or "smb://" in s_val:
                     findings.append((f"{C_RED}[OBJ] Meta Leak{C_RESET}", f"{k}: {s_val}"))
                elif "Producer" in k or "Creator" in k:
                     # Just informative
                     findings.append((f"{C_YELLOW}[OBJ] Software{C_RESET}", s_val))

        # B. Deep Object Scan for /F keys
        # We limit the loop to avoid hanging on massive files, but for regular docs its fine
        for obj in pdf.objects:
            if isinstance(obj, Dictionary):
                if "/F" in obj:
                    val = clean_string(obj["/F"])
                    if "\\\\" in val or ":" in val:
                         if not is_garbage(val):
                            findings.append((f"{C_RED}[OBJ] Embedded File{C_RESET}", val))
                            
    except Exception as e:
        # Many PDFs are malformed, we just skip object analysis if it fails
        pass

    # --- OUTPUT SUMMARY ---
    # Deduplicate findings
    unique_findings = sorted(list(set(findings)))
    
    if unique_findings:
        for cat, val in unique_findings:
            # Final noise filter
            if "adobe.com" in val or "w3.org" in val or "purl.org" in val:
                continue
            print(f"    |-- {cat}: {val}")
    else:
        print(f"    |-- {C_YELLOW}No significant artifacts found.{C_RESET}")
    print("")

def main():
    print_banner()
    
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    files = []
    
    if os.path.isfile(target):
        files.append(target)
    elif os.path.isdir(target):
        for root, _, fs in os.walk(target):
            for f in fs:
                if f.lower().endswith(".pdf"):
                    files.append(os.path.join(root, f))
    
    if not files:
        print(f"{C_RED}[!] No PDF files found.{C_RESET}")
        return
        
    print(f"{C_GREEN}[+] Found {len(files)} files to scan.{C_RESET}\n")
    
    for f in files:
        analyze_file(f)

if __name__ == "__main__":
    main()
