#!/usr/bin/env python3

import os
import subprocess
import datetime
import socket

def run_command(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True)
        return result.strip()
    except subprocess.CalledProcessError:
        return "Command failed or not supported."

def save_to_file(folder, filename, content):
    filepath = os.path.join(folder, filename)
    with open(filepath, "w") as f:
        f.write(content)

def main():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = socket.gethostname()
    folder = f"ir_data_{hostname}_{timestamp}"
    os.makedirs(folder, exist_ok=True)

    print(f"[+] Collecting Incident Response data in folder: {folder}")

    #system uptime
    uptime = run_command("uptime")
    save_to_file(folder, "system_uptime.txt", uptime)

    #loggedin users
    users = run_command("who")
    save_to_file(folder, "logged_in_users.txt", users)

    #running processes
    processes = run_command("ps aux --sort=-%cpu")
    save_to_file(folder, "running_processes.txt", processes)

    #network connections
    netstat = run_command("netstat -tunap")
    save_to_file(folder, "network_connections.txt", netstat)

    #recent syslog 
    syslog_path = "/var/log/syslog"
    if os.path.exists(syslog_path):
        syslog = run_command(f"tail -n 100 {syslog_path}")
        save_to_file(folder, "syslog_recent.txt", syslog)
    else:
        save_to_file(folder, "syslog_recent.txt", "Syslog file not found or inaccessible.")

    #basic file integrity (hashes key system files)
    files_to_hash = ["/etc/passwd", "/etc/shadow", "/bin/bash", "/usr/bin/python3"]
    hashes = []
    for file in files_to_hash:
        if os.path.exists(file):
            hash_val = run_command(f"sha256sum {file}")
            hashes.append(hash_val)
        else:
            hashes.append(f"{file} not found.")
    save_to_file(folder, "file_hashes.txt", "\n".join(hashes))

    print("[+] Data collection complete!")

if __name__ == "__main__":
    main()
