import re
import sys
import urllib.request
import urllib.error
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
import argparse
import os
import ipaddress

import yaml

# Brute force rule: THRESHOLD or more failed logins from one IP within WINDOW.
WINDOW = timedelta(seconds=60)
THRESHOLD = 5

# ANSI terminal color codes used by tag().
RESET = "\033[0m"
COLORS = {
    "SSH": "\033[33m",         # yellow
    "WEB": "\033[34m",         # blue
    "CORRELATED": "\033[1;31m",# bold red
    "WARN": "\033[31m",        # red
    "OK": "\033[32m",          # green
    "SUMMARY": "\033[36m",     # cyan
}
# Only color output in a real terminal (not when piped to a file), and
# respect the NO_COLOR convention (https://no-color.org).
USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ

# IP -> geolocation result, so each IP is looked up at most once per run.
cache = {}

def tag(name):
    """Return an output label like "[SSH]", colored when USE_COLOR is on.

        `name` must be a key of COLORS.
    """
    if not USE_COLOR:
        return f"[{name}]"
    return f"{COLORS[name]}[{name}]{RESET}"

def parse_timestamp(timestamp):
    """Parse a timestamp string into a datetime, or return None.

        Handles ISO 8601, classic syslog ("Nov 28 05:11:25", year assumed
        to be the current one) and web log ("28/Nov/2026:10:15:40 +0000").
    """
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
    """Extract the timestamp from the start of an auth log line, or return None.

        Tries the first word first (ISO 8601 format, e.g. "2026-11-28T05:11:25"),
        then the first three words (syslog format, e.g. "Nov 28 05:11:25").
    """
    parts = line.split()
    when = parse_timestamp(parts[0]) if parts else None
    if when is None:
        when = parse_timestamp(" ".join(parts[:3]))
    return when

def lookup_ip(ip):
    """Look up an IP's location using the free ip-api.com service.

        Returns a dict with "country", "city", "ip" and "isp" keys, or a dict
        with only an "error" key if the request fails (no network, timeout,
        bad response). Results, including errors, are cached so the same IP
        is never requested twice.
    """
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

def matches_selection(selection, event):
    """Return True if `event` (a dict of fields) matches a Sigma selection.

        Each selection key is a field name with an optional modifier, e.g.
        "message|contains". Every key must match (AND). If a key lists several
        values, any one of them is enough (OR). Comparison ignores case.
        Supported modifiers: none (exact match) and "contains".
    """
    for key, expected in selection.items():
        # "message|contains" -> field="message", modifier="contains"
        field, _, modifier = key.partition("|")
        value = str(event.get(field, "")).lower()
        # A rule value can be a single item or a list; treat both as a list.
        expected_values = expected if isinstance(expected, list) else [expected]
        expected_values = [str(e).lower() for e in expected_values]
        if modifier == "contains":
            matched = any(e in value for e in expected_values)
        elif modifier == "":
            matched = any(e == value for e in expected_values)
        else:
            raise ValueError(f"Unknown modifier: {modifier!r} in rule key {key!r}")
        if not matched:
            return False
    return True

def is_valid_ip(ip):
    """Return True if `ip` is a valid IPv4 or IPv6 address.

        Needed because the log regexes accept any mix of hex digits, dots
        and colons, so they can capture junk like "1.2.3" or ":::".
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def load_selection(path):
    """Load a Sigma rule file and return its detection selection.

        Only simple rules are supported: a single 'selection' block with
        'condition: selection'. Exits with a clear message if the file is
        missing, is not valid YAML, or lacks the expected structure.
    """
    try:
        with open(path, "r") as f:
            rule = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Sigma rule file not found: {path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing Sigma rule file: {e}")
        sys.exit(1)

    try:
        selection = rule["detection"]["selection"]
    except (KeyError, TypeError):
        print(f"Invalid Sigma rule structure in file: {path}")
        sys.exit(1)
    if not isinstance(selection, dict):
        print(f"Invalid selection structure in Sigma rule file: {path}")
        sys.exit(1)
    for key in selection:
        _, _, modifier = key.partition("|")
        if modifier not in ("", "contains"):
            print(f"Unsupported modifier {modifier!r} in rule key {key!r} ({path})")
            sys.exit(1)
    return selection

def main():
    """Run the detector from the command line.

        1. Read the auth log and alert on IPs with too many failed SSH
           logins in a short time (see WINDOW and THRESHOLD).
        2. Optionally read a web log and flag requests to known attack paths.
        3. Report IPs that showed up in both, then print a summary and
           warnings about lines that could not be read.
    """
    # Captures the attacker IP from lines like
    # "... Failed password for root from 203.0.113.5 port 22 ssh2".
    ssh_pattern = re.compile(
        r"Failed password .* from (?P<ip>[0-9a-fA-F:.]+)"
    )
    # syslog collapses duplicates into "message repeated N times: [...]",
    # so one line can stand for N failed logins.
    repeat_pattern = re.compile(r"message repeated (?P<count>\d+) times")
    # Apache/Nginx common log format. Groups:
    # ip, 2=timestamp, 3=method, 4=path, 5=status code, 6=response size.
    web_pattern = re.compile(
        r'^(?P<ip>[0-9a-fA-F:.]+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+)'
    )
    suspicious_paths = {"/wp-login.php", "/admin", "/.env", "/phpmyadmin"}
    web_hits = defaultdict(list)  # IP -> suspicious paths it requested (no repeats)
    recent = defaultdict(deque)   # IP -> times of its failed logins inside the current window
    alerted = set()               # IPs currently over the threshold (stops repeat alerts)
    attackers = set()             # every IP that triggered an SSH alert, used for correlation
    parser = argparse.ArgumentParser(description="Detect SSH brute force attacks from auth-logs and web-logs.")
    parser.add_argument("--auth", required=True, help="Path to the auth log file")
    parser.add_argument("--web", help="Path to the web log file (optional)")
    parser.add_argument("--rules", help="Path to a Sigma rule file (optional)")
    args = parser.parse_args()

    auth_lines_read = 0
    auth_failed_logins = 0
    auth_skipped_lines = 0
    brute_force_alerts = 0

    web_lines_read = 0
    web_suspicious_hits = 0
    web_matched = 0
    web_skipped_lines = 0

    # Sigma selection to match against. Without --rules, use a default rule
    # equivalent to the built-in SSH check.
    sel = load_selection(args.rules) if args.rules else {"message|contains": "Failed password"}

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
                        auth_skipped_lines += count
                        continue
                    ip = match.group("ip")
                    if not is_valid_ip(ip):
                        auth_skipped_lines += count
                        continue
                    # Sliding window: record this attempt (count times if it was a
                    # "repeated" line), then drop attempts older than WINDOW.
                    for _ in range(count):
                        recent[ip].append(when)
                    cutoff = when - WINDOW

                    while recent[ip][0] < cutoff:
                        recent[ip].popleft()
                    if len(recent[ip]) >= THRESHOLD:
                        # Alert once when the IP crosses the threshold, not on every
                        # extra attempt after that.
                        if ip not in alerted:
                            brute_force_alerts += 1
                            info = lookup_ip(ip)
                            alerted.add(ip)
                            attackers.add(ip)
                            print(f"{tag('SSH')} {ip} ({info.get('country', '?')}, {info.get('city', '?')}) {len(recent[ip])}"
                                f" failed attempts within {int(WINDOW.total_seconds())}s at {when}")
                    else:
                        # The IP dropped below the threshold, so a new burst
                        # later will raise a new alert.
                        alerted.discard(ip)

        if args.web:
            with open(args.web) as f:
                for line in f:
                    web_lines_read += 1
                    web_match = web_pattern.search(line)
                    if web_match:
                        web_ip = web_match.group("ip")
                        if not is_valid_ip(web_ip):
                            web_skipped_lines += 1
                            continue
                        web_when = parse_timestamp(web_match.group(2))
                        if web_when is None:
                            web_skipped_lines += 1
                            continue
                        web_path = web_match.group(4)
                        web_matched += 1

                        if web_path in suspicious_paths:
                            if web_path not in web_hits[web_ip]:
                                web_suspicious_hits += 1
                                web_hits[web_ip].append(web_path)
                                print(f"{tag('WEB')} {web_ip} accessed {web_path} at {web_when}")

        # Correlation: IPs that brute forced SSH and also probed the web server.
        both = attackers & web_hits.keys()
        # Failed logins that were actually checked (had a readable time and valid IP).
        analyzed = auth_failed_logins - auth_skipped_lines
        for ip in both:
            info = lookup_ip(ip)
            print(f"{tag('CORRELATED')} {ip} ({info.get('country', '?')}, {info.get('city', '?')}): "
                  f"SSH brute force + web paths {web_hits[ip]}")
        print(f"{tag('SUMMARY')} auth log: {auth_lines_read} lines, {auth_failed_logins} failed logins, "
              f"{brute_force_alerts} alerts")
        if args.web:
            if web_skipped_lines:
                print(f"{tag('WARN')} {web_skipped_lines} web log lines skipped: unreadable format")
            if web_matched:
                print(f"{tag('SUMMARY')} web log: {web_lines_read} lines, {web_matched} matched, "
                      f"{web_suspicious_hits} suspicious hits")
                if not both:
                    print(f"{tag('OK')} No correlated activity")
            if not web_matched:
                print(f"{tag('WARN')} No web log lines matched the expected format. Wrong log or unsupported format?")
        if auth_skipped_lines:
            if auth_skipped_lines == 1:
                print(f"{tag('WARN')} {auth_skipped_lines} failed login skipped: unreadable format or invalid IP")
            else:
                print(f"{tag('WARN')} {auth_skipped_lines} failed logins skipped: unreadable format or invalid IP")
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