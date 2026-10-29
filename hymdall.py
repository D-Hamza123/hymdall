import re
import sys
import urllib.request
import urllib.error
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
import argparse
import os

WINDOW = timedelta(seconds=60)
THRESHOLD = 5
RESET = "\033[0m"
COLORS = {
    "SSH": "\033[33m",         # yellow
    "WEB": "\033[34m",         # blue
    "CORRELATED": "\033[1;31m",# bold red
    "WARN": "\033[31m",        # red
    "OK": "\033[32m",          # green
    "SUMMARY": "\033[36m",     # cyan
}
USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ

cache = {}

def tag(name):
    if not USE_COLOR:
        return f"[{name}]"
    return f"{COLORS[name]}[{name}]{RESET}"

def parse_timestamp(timestamp):
    try:
        return datetime.fromisoformat(timestamp)
    except ValueError:
        pass
    try:
        return datetime.strptime(f"{datetime.now().year} {timestamp}", "%Y %b %d %H:%M:%S")
    except ValueError:
        pass
    try:
        return datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
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
    repeat_pattern = re.compile(r"message repeated (?P<count>\d+) times")
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

    auth_lines_read = 0
    auth_failed_logins = 0
    auth_skipped_lines = 0
    brute_force_alerts = 0

    web_lines_read = 0
    web_suspicious_hits = 0
    web_matched = 0
    web_skipped_lines = 0

    try:
        with open(args.auth) as f:
            for line in f:
                auth_lines_read += 1
                match = ssh_pattern.search(line)
                if match:
                    rep = repeat_pattern.search(line)
                    count = int(rep.group("count")) if rep else 1
                    auth_failed_logins += count
                    when = get_time(line)
                    if when is None:
                        auth_skipped_lines += 1
                        continue
                    ip = match.group(1)
                    for _ in range(count):
                        recent[ip].append(when)
                    cutoff = when - WINDOW

                    while recent[ip][0] < cutoff:
                        recent[ip].popleft()
                    if len(recent[ip]) >= THRESHOLD:
                        if ip not in alerted:
                            brute_force_alerts += 1
                            info = lookup_ip(ip)
                            alerted.add(ip)
                            attackers.add(ip)
                            print(f"{tag('SSH')} {ip} ({info.get('country', '?')}, {info.get('city', '?')}) {len(recent[ip])}"
                                f" failed attempts within {int(WINDOW.total_seconds())}s at {when}")
                    else:
                        alerted.discard(ip)

        if args.web:
            with open(args.web) as f:
                for line in f:
                    web_lines_read += 1
                    web_match = web_pattern.search(line)
                    if web_match:
                        web_matched += 1
                        web_ip = web_match.group(1)
                        web_when = parse_timestamp(web_match.group(2))
                        if web_when is None:
                            web_skipped_lines += 1
                            continue
                        web_path = web_match.group(4)

                        if web_path in suspicious_paths:
                            if web_path not in web_hits[web_ip]:
                                web_suspicious_hits += 1
                                web_hits[web_ip].append(web_path)
                                print(f"{tag('WEB')} {web_ip} accessed {web_path} at {web_when}")

        both = attackers & web_hits.keys()
        analyzed = auth_failed_logins - auth_skipped_lines
        for ip in both:
            print(f"{tag('CORRELATED')} {ip} ({lookup_ip(ip).get('country', '?')}, {lookup_ip(ip).get('city', '?')}): "
                  f"SSH brute force + web paths {web_hits[ip]}")
        print(f"{tag('SUMMARY')} auth log: {auth_lines_read} lines, {auth_failed_logins} failed logins, "
              f"{brute_force_alerts} alerts")
        if args.web:
            if web_skipped_lines:
                print(f"{tag('WARN')} {web_skipped_lines} web log lines skipped: unreadable format")
            if web_matched:
                print(f"{tag('SUMMARY')} web log: {web_lines_read} lines, {web_matched} matched,"
                      f"{web_suspicious_hits} suspicious hits")
                if not both:
                    print(f"{tag('OK')} No correlated activity")
            if not web_matched:
                print(f"{tag('WARN')} No web log lines matched the expected format. Wrong log or unsupported format?")
        if auth_skipped_lines:
            print(f"{tag('WARN')} {auth_skipped_lines} failed logins skipped: unreadable timestamp")
        if brute_force_alerts == 0:
            if auth_failed_logins == 0:
                print(f"{tag('WARN')} No failed logins recognized. Wrong log, or unsupported format?")
            elif analyzed == 0:
                print(f"{tag('WARN')} Failed logins found but none could be analyzed")
            else:
                print(f"{tag('OK')} No SSH brute force detected.")

    except FileNotFoundError as e:
        print(f"File not found: {e}")
        sys.exit(1)
    except PermissionError as e:
        print(f"Permission denied: {e}. Try running with `sudo`, or copy the log files to a readable location.")
        sys.exit(1)

if __name__ == "__main__":
    main()