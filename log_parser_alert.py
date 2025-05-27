#!/usr/bin/env python3

import re
import argparse
from datetime import datetime, timedelta
import logging
from collections import defaultdict

# Set up logging for script info/debug
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# Regex pattern simulating SSH auth log failed attempts:
# Example line: "May 26 12:00:01 server sshd[12345]: Failed password for invalid user root from 192.168.1.10 port 22 ssh2"
FAILED_LOGIN_REGEX = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[.*\]: Failed password for (invalid user )?\S+ from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr":4, "May":5, "Jun":6,
    "Jul":7, "Aug":8, "Sep":9, "Oct":10, "Nov":11, "Dec":12
}

def parse_log(file_path, threshold, time_window_minutes):
    # Dictionary: IP -> list of datetime objects of failures
    failed_attempts = defaultdict(list)
    
    alert_ips = set()
    current_year = datetime.now().year

    with open(file_path, 'r') as f:
        for line in f:
            match = FAILED_LOGIN_REGEX.match(line)
            if match:
                month = MONTHS[match.group('month')]
                day = int(match.group('day'))
                time_str = match.group('time')
                ip = match.group('ip')

                # Construct datetime object for this log line
                timestamp_str = f"{current_year}-{month:02d}-{day:02d} {time_str}"
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

                # Append this failure timestamp for the IP
                failed_attempts[ip].append(timestamp)

                # Filter timestamps to within time window (now minus window)
                window_start = timestamp - timedelta(minutes=time_window_minutes)
                recent_attempts = [t for t in failed_attempts[ip] if t >= window_start]
                failed_attempts[ip] = recent_attempts

                # Check if threshold exceeded within time window
                if len(recent_attempts) >= threshold and ip not in alert_ips:
                    print(f"[ALERT] IP {ip} has {len(recent_attempts)} failed login attempts within last {time_window_minutes} minutes (last attempt: {timestamp})")
                    alert_ips.add(ip)

    # Summary report
    print("\nSummary of failed login attempts per IP (within last time window):")
    for ip, timestamps in failed_attempts.items():
        print(f"{ip}: {len(timestamps)} failed attempts")

def main():
    parser = argparse.ArgumentParser(description="Parse SSH auth logs for failed login attempts and alert on suspicious IPs.")
    parser.add_argument("logfile", help="Path to the log file to parse")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Number of failed attempts to trigger alert")
    parser.add_argument("-w", "--window", type=int, default=10, help="Time window in minutes to count failed attempts")

    args = parser.parse_args()

    logging.info(f"Starting to parse log file: {args.logfile}")
    logging.info(f"Alert threshold set to {args.threshold} failed attempts within {args.window} minutes")

    parse_log(args.logfile, args.threshold, args.window)

if __name__ == "__main__":
    main()
