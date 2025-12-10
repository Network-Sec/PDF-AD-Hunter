# PDF-AD-Hunter
OSINT for Active Directory artefacts in PDF docs. Download them all to a folder and run the script or provide single file path or dir path.

```bash
$ python3 pdf_ad_hunter.py .


    ____  ____  _____       _    ____
   |  _ \|  _ \|  ___|     / \  |  _ \
   | |_) | | | | |_ _____ / _ \ | | | |
   |  __/| |_| |  _|_____/ ___ \| |_| |
   |_|   |____/|_|      /_/   \_\____/
           INTERNAL INFRASTRUCTURE HUNTER v5.0


[+] Found 107 files to scan.

[*] Target: Q3_Financial_Draft.pdf
    |-- [OBJ] Meta Leak: Title: \\FS-FINANCE-01\DeptShares$\Restricted\Q3_2024.docx
    |-- [OBJ] Software: Microsoft Word for Office 365
    |-- [RAW] UNC Path: \\FS-FINANCE-01\DeptShares$\Restricted\
    |-- [XML] Creator Tool: Microsoft Word
    |-- [XML] History Log: saved to \\CORP-DC01\Home\jsmith\My Documents\Work\Report.pdf
    |-- [XML] UNC Path: \\CORP-DC01\Home\jsmith\My Documents\Work\Report.pdf

[*] Target: Employee_Onboarding_Checklist.pdf
    |-- [OBJ] Embedded File: \\LEGACY-APP-02\Templates\GlobalMacros.dotm
    |-- [OBJ] Software: Adobe Acrobat Pro DC 19.0
    |-- [RAW] UNC Path: \\intranet.corp.local\netlogon\scripts\setup.bat
    |-- [XML] History Log: converted from application/msword
    |-- [XML] History Log: saved to \\FILESRV\HR\Policies\2023\Checklist.pdf

[*] Target: Scan_Xerox_00412.pdf
    |-- [RAW] UNC Path: \\192.168.50.10\Public\Scans\
    |-- [XML] Creator Tool: Xerox WorkCentre 7855

[*] Target: 0002_de.pdf
    |-- [OBJ] Software: Adobe InDesign CC 2017 (Macintosh)
    |-- [XML] Creator Tool: Adobe InDesign CC 2017 (Macintosh)

[*] Target: 0002_de.pdf
    |-- [RAW] UNC Path: \\\\\\\347\347\347888...\272\272\272\270\270
    |-- [XML] History Log: from application/postscript to application/vnd.adobe.illustrator
    |-- [XML] History Log: from application/x-indesign to application/pdf
    |-- [OBJ] Software: Adobe InDesign CC 2017 (Macintosh)
    |-- [OBJ] Software: Adobe PDF Library 15.0
    |-- [XML] Creator Tool: Adobe Illustrator CC 2015.3 (Macintosh)
    |-- [XML] Creator Tool: Adobe Illustrator CS6 (Macintosh)
    |-- [XML] Creator Tool: Adobe Illustrator(R) 8.0
    |-- [XML] Creator Tool: Adobe InDesign CC 2017 (Macintosh)
```
