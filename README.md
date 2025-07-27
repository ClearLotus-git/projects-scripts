# Bludit 3.9.2 - Authentication Bruteforce Mitigation Bypass

This is a custom Metasploit module for exploiting a vulnerability in Bludit CMS v3.9.2 and below. The vulnerability allows bypassing the anti-brute force mechanism by manipulating HTTP headers (`X-Forwarded-For`).

## 📌 CVE Reference
- **CVE-2019-17240**
- [Original Write-up](https://rastating.github.io/bludit-brute-force-mitigation-bypass/)
- [Patch](https://github.com/bludit/bludit/pull/1090)

## 📁 Files Included
- `bludit_bypass.rb`: The Metasploit exploit module

## 🛠 Usage

1. Copy `bludit_bypass.rb` into your local Metasploit modules folder, e.g.:
   ```bash
   cp bludit_bypass.rb ~/.msf4/modules/exploits/custom/
   ```

2. Reload Metasploit modules:
   ```bash
   msfconsole
   reload_all
   ```

3. Use the module:
   ```bash
   use exploit/custom/bludit_bypass
   set RHOSTS <target-ip>
   set TARGETURI /
   set BLUDITUSER <username>
   set PASSWORDS /path/to/passwords.txt
   run
   ```

## 🧑‍💻 Authors
- `rastating` — original discovery
- `0ne-nine9` — Metasploit module adaptation

## ⚠️ Disclaimer
This code is provided for educational purposes only. Unauthorized use against systems you do not own is illegal.
