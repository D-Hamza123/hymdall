import re
import requests
from collections import defaultdict, deque
from datetime import datetime, timedelta

WINDOW = timedelta(seconds=60)
THRESHOLD = 5

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
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        result = {
            "country": data.get("country", "?"),
            "city": data.get("city", "?"),
            "ip": data.get("query", "?"),
            "isp": data.get("isp", "?")
        }
    except requests.RequestException as e:
        result = {"error": str(e)}

    cache[ip] = result
    return result

def parse_web_time(text):
    return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")

def parse_time(text):
    return datetime.strptime("2026 " + text,"%Y %b %d %H:%M:%S")


with open("sample-logs/auth logs/auth-1.log") as f:
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
            else:
                alerted.discard(ip)

with open("sample-logs/web logs/web-log1.log") as f:
    for line in f:
        web_match = web_pattern.search(line)
        if web_match:
            web_ip = web_match.group(1)
            web_when = parse_web_time(web_match.group(2))
            web_path = web_match.group(4)

            if web_path in suspicious_paths:
                if web_path not in web_hits[web_ip]:
                    web_hits[web_ip].append(web_path)
            else:
                pass

found_attackers = list()
for ip in attackers:
    if ip in web_hits:
        found_attackers.append(ip)
if found_attackers:
    if len(found_attackers) > 1:
        print(f"These are attacks from: {', '.join(found_attackers)}")
    else:
        print(f"This is an attack from: {found_attackers[0]}")
