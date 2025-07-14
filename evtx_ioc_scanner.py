import os
import sys
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

# Define suspicious indicators for matching
suspicious_keywords = ["powershell", "rundll32", "mimikatz", "wermgr.exe", "dsrm.exe"]
interesting_event_ids = ["4624", "4625", "4688", "7045", "4662"]

def parse_evtx(file_path):
    try:
        with Evtx(file_path) as log:
            for record in log.records():
                try:
                    xml = ET.fromstring(record.xml())
                    event_id = xml.find(".//EventID").text
                    if event_id in interesting_event_ids:
                        data = {
                            "EventID": event_id,
                            "TimeCreated": xml.find(".//TimeCreated").attrib.get("SystemTime"),
                            "Computer": xml.find(".//Computer").text,
                            "RawText": record.xml()
                        }

                        # Look for known suspicious keywords
                        if any(keyword.lower() in record.xml().lower() for keyword in suspicious_keywords):
                            print(f"[!] Suspicious Keyword Match — {keyword} in EventID {event_id}")
                            print(f"    Time: {data['TimeCreated']}")
                            print(f"    Host: {data['Computer']}")
                            print()
                except Exception as e:
                    continue
    except Exception as e:
        print(f"Failed to parse {file_path}: {str(e)}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python evtx-ioc-scanner.py <evtx_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.isfile(file_path):
        print("File does not exist.")
        sys.exit(1)

    print(f"[+] Scanning {file_path}...\n")
    parse_evtx(file_path)
    print("\n[+] Scan complete.")

if __name__ == "__main__":
    main()
