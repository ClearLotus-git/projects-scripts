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

```
git clone https://github.com/ClearLotus-git/projects-scripts.git
cd projects-scripts/helperbot

```

3. Run the bot:

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

## Adding Your Own Playbooks

The SOC Helper Bot is designed to be extensible. You can add your own detection playbooks by editing the playbooks.json file.
Each playbook follows this format:

```
{
  "keyword": "keyword to match",
  "technique": "MITRE ATT&CK ID - Technique Name",
  "logs": ["Relevant log source 1", "Relevant log source 2"],
  "steps": [
    "Step 1 of the investigation",
    "Step 2 of the investigation",
    "Step 3 of the investigation"
  ]
}
```

## LICENSE

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.











