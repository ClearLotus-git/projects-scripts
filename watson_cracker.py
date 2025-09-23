# used for cracking NTLM for CTF

import hashlib
import datetime

# Target NTLM hash
target_hash = "532303a6fa70b02c905f950b60d7da51"

def ntlm_hash(password):
    return hashlib.new('md4', password.encode('utf-16le')).hexdigest()

# Search over a broad date range (April -> Sept 2025)
start = datetime.datetime(2025, 4, 1, 0, 0, 0)
end   = datetime.datetime(2025, 9, 25, 0, 0, 0)

delta = datetime.timedelta(seconds=1)
current = start

while current <= end:
    candidate = "Watson_" + current.strftime("%Y%m%d%H%M%S")
    if ntlm_hash(candidate) == target_hash:
        print(f"[+] Match found: {candidate}")
        break
    current += delta
