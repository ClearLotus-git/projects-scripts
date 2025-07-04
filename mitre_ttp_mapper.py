
import os
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx  # Requires `python-evtx`
from collections import defaultdict
import argparse

MITRE_TTP_MAP = {
    '4624': {
        'description': 'Successful Logon',
        'tactic': 'Initial Access / Lateral Movement',
        'technique': 'T1078 - Valid Accounts',
        'details': {
            '10': 'RemoteInteractive (RDP) - T1021.001',
            '3': 'Network Logon (SMB/WMI) - T1021.002/003',
            '5': 'Service logon (Scheduled Tasks)'
        }
    },
    '4697': {
        'description': 'Service Installed',
        'tactic': 'Persistence / Privilege Escalation',
        'technique': 'T1543.003 - Windows Service'
    },
    '5142': {
        'description': 'Network Share Added',
        'tactic': 'Lateral Movement',
        'technique': 'T1021.002 - SMB/Windows Admin Shares'
    },
    '4719': {
        'description': 'Audit Policy Changed',
        'tactic': 'Defense Evasion',
        'technique': 'T1562.002 - Disable Windows Event Logging'
    },
    '4688': {
        'description': 'Process Created',
        'tactic': 'Execution',
        'technique': 'T1059 - Command and Scripting Interpreter'
    }
}

def map_ttp(event_id, logon_type=None):
    entry = MITRE_TTP_MAP.get(str(event_id))
    if not entry:
        return None

    result = {
        'Event ID': event_id,
        'Description': entry['description'],
        'Tactic': entry['tactic'],
        'Technique': entry['technique']
    }

    if event_id == '4624' and logon_type:
        detail = entry['details'].get(str(logon_type))
        if detail:
            result['Logon Detail'] = detail

    return result

def extract_events(evtx_path):
    with Evtx(evtx_path) as log:
        for record in log.records():
            try:
                xml = ET.fromstring(record.xml())
                event_id = xml.find("System/EventID").text
                time = xml.find("System/TimeCreated").attrib['SystemTime']

                logon_type = None
                if event_id == '4624':
                    for data in xml.findall("EventData/Data"):
                        if data.attrib.get('Name') == 'LogonType':
                            logon_type = data.text
                            break

                mapped = map_ttp(event_id, logon_type)
                if mapped:
                    mapped['Time'] = time
                    yield mapped

            except Exception as e:
                continue

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directory', required=True, help='Directory containing .evtx files')
    args = parser.parse_args()

    for file in os.listdir(args.directory):
        if file.endswith('.evtx'):
            path = os.path.join(args.directory, file)
            print(f"\n--- Events from {file} ---")
            for entry in extract_events(path):
                print(f"[{entry['Time']}] {entry['Event ID']} - {entry['Description']} => {entry['Technique']} ({entry['Tactic']})")
                if 'Logon Detail' in entry:
                    print(f"    Logon Detail: {entry['Logon Detail']}")
