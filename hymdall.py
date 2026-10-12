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

parser = argparse.ArgumentParser(description="Detect SSH brute force attacks from auth-logs and web-logs.")
parser.add_argument("--auth", required=True, help="Path to the auth log file")
parser.add_argument("--web", help="Path to the web log file (optional)")
args = parser.parse_args()

# print(args.auth)
# print(args.web)

cache = {}

pattern = re.compile(
    r"^(\w{3}\s+\d+\s[\d:]{8}) .* Failed password .* from (\d+\.\d+\.\d+\.\d+)"
)
web_pattern = re.compile(
    r'^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+)'
)
suspicious_paths = {"/wp-login.php", "/admin", "/.env", "/phpmyadmin"}
web_hits = defaultdict(list)
recent = defaultdict(deque)
alerted = set()
attackers = set()

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

def parse_web_time(text):
    return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")

def parse_time(text):
    return datetime.strptime("2026 " + text,"%Y %b %d %H:%M:%S")

try:
    with open(args.auth) as f:
        for line in f:
            match = pattern.search(line)
            if match:
                when = parse_time(match.group(1))
                ip = match.group(2)
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
                    web_when = parse_web_time(web_match.group(2))
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

