import re
import sys
import urllib.request
import urllib.error
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
import argparse

WINDOW = timedelta(seconds=60)
THRESHOLD = 5

TIME_FORMATS = [
    "%b %d %H:%M:%S", # e.g., "Jan 12 15:04:05"
    "%Y-%m-%dT%H:%M:%S.%f%z", # e.g., "2023-01-12T15:04:05.123456+0000"
    "%d/%b/%Y:%H:%M:%S %z", # e.g., "12/Jan/2023:15:04:05 +0000"
]

cache = {}

def parse_timestamp(timestamp):
    try:
        return datetime.fromisoformat(timestamp)
    except ValueError:
        pass
    for fmt in TIME_FORMATS:
        try:
            dt = datetime.strptime(timestamp, fmt)
        except ValueError:
            continue
        if dt.year == 1900:
            dt = dt.replace(year=datetime.now().year)
        return dt
    return None

def get_time(line):
    parts = line.split()
    when = parse_timestamp(parts[0]) if parts else None
    if when is None:
        when = parse_timestamp(" ".join(parts[:3]))
    return when

def lookup_ip(ip):
    if ip in cache:
        return cache[ip]
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}", timeout=3) as response:
            data = json.load(response)
        result = {
            "country": data.get("country", "?"),
            "city": data.get("city", "?"),
            "ip": data.get("query", "?"),
            "isp": data.get("isp", "?")
        }
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        result = {"error": str(e)}

    cache[ip] = result
    return result

def main():
    ssh_pattern = re.compile(
        r"Failed password .* from (\d+\.\d+\.\d+\.\d+)"
    )
    web_pattern = re.compile(
        r'^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+)'
    )
    suspicious_paths = {"/wp-login.php", "/admin", "/.env", "/phpmyadmin"}
    web_hits = defaultdict(list)
    recent = defaultdict(deque)
    alerted = set()
    attackers = set()
    parser = argparse.ArgumentParser(description="Detect SSH brute force attacks from auth-logs and web-logs.")
    parser.add_argument("--auth", required=True, help="Path to the auth log file")
    parser.add_argument("--web", help="Path to the web log file (optional)")
    args = parser.parse_args()
    try:
        with open(args.auth) as f:
            for line in f:
                match = ssh_pattern.search(line)
                if match:
                    when = get_time(line)
                    if when is None:
                        continue
                    ip = match.group(1)
                    recent[ip].append(when)
                    cutoff = when - WINDOW

                    while recent[ip][0] < cutoff:
                        recent[ip].popleft()
                    if len(recent[ip]) >= THRESHOLD:
                        if ip not in alerted:
                            info = lookup_ip(ip)
                            alerted.add(ip)
                            attackers.add(ip)
                            print(f"[SSH] {ip} ({info.get('country', '?')}, {info.get('city', '?')}) {len(recent[ip])}"
                                f" failed attempts within {int(WINDOW.total_seconds())}s at {when}")
                    else:
                        alerted.discard(ip)
        if args.web:
            with open(args.web) as f:
                for line in f:
                    web_match = web_pattern.search(line)
                    if web_match:
                        web_ip = web_match.group(1)
                        web_when = parse_timestamp(web_match.group(2))
                        web_path = web_match.group(4)

                        if web_path in suspicious_paths:
                            if web_path not in web_hits[web_ip]:
                                web_hits[web_ip].append(web_path)
                                print(f"[WEB] {web_ip} accessed {web_path} at {web_when}")

    except FileNotFoundError as e:
        print(f"File not found: {e}")
        sys.exit(1)
    except PermissionError as e:
        print(f"Permission denied: {e}. Try running with `sudo`, or copy the log files to a readable location.")
        sys.exit(1)

    for ip in attackers & web_hits.keys():
        print(f"[CORRELATED] {ip} ({lookup_ip(ip).get('country', '?')}, {lookup_ip(ip).get('city', '?')}): "
                f"SSH brute force + web paths {web_hits[ip]}")

if __name__ == "__main__":
    main()