# SOC Helper Bot

A lightweight python tool that assists SOC in mapping alerts or log descriptions to **<MITRE ATT&CK techniques**, 
relevant **log sources**, and suggested **investigation steps**. 

## Features
-  Maps alert keywords to **MITRE ATT&CK techniques**  
-  Suggests relevant **log sources / event IDs**  
-  Provides **step-by-step triage guidance**  
-  Runs as a simple **CLI tool** (no external dependencies)

## Installation 

1. Clone the repository:

2. Run the bot:

`python3 soc_helper.py`

## Usage:

```
┌──(lotus㉿lotus-pc)-[~/projects]
└─$ python3 soc_helper.py
Enter alert/log description: Suspicious powershell execution detected
MITRE Technique: T1059.001 - PowerShell
Relevant Logs: Sysmon Event ID 1 (Process Creation), Windows Security Log 4688
Investigation Steps:
  1. Check parent process of PowerShell execution
  2. Look for obfuscation (Base64, IEX, long strings)
  3. Pivot on user account and machine for lateral movement

```
