# hymdall

## Overview
hymdall is a command-line tool that scans server log files for signs of attack. It reads an SSH authentication log (and optionally a web server log), flags brute force login attempts and probes of sensitive web paths, and points out IP addresses that did both. It is aimed at system administrators, security analysts, and developers who want a quick read on what is hitting their servers.

## How It Works
1. **Auth log scan**: hymdall reads the auth log you pass with `--auth` and picks out failed SSH password attempts.
2. **Brute force detection**: if one IP fails to log in **5 or more times within 60 seconds**, hymdall raises an `[SSH]` alert and looks up the IP's country and city.
3. **Web log scan (optional)**: if you pass a web log with `--web`, hymdall flags requests to known attack targets: `/wp-login.php`, `/admin`, `/.env` and `/phpmyadmin`.
4. **Correlation**: any IP that triggered an SSH alert *and* probed one of those web paths is reported as `[CORRELATED]`, since it is likely the same attacker working on both services.
5. **Summary**: hymdall prints line counts and alert totals, plus warnings about lines it could not read.

## Features
- **SSH brute force detection**: sliding 60-second window per IP, with one alert per burst instead of one per attempt. Collapsed syslog lines ("message repeated N times") are counted as N attempts.
- **Web probe detection**: reports each suspicious path once per IP.
- **Cross-log correlation**: links SSH attackers to web scanners by IP.
- **IP geolocation**: shows the country and city of alerting IPs (see [Privacy and network use](#privacy-and-network-use)).
- **IPv4 and IPv6 support**: malformed IPs are skipped and counted in the warnings.
- **Clear diagnostics**: warns when a log looks like the wrong file or an unsupported format, instead of silently reporting "nothing found".
- **Sigma rule loading (experimental)**: see [Sigma rules](#sigma-rules).

## File Structure
- `LICENSE`: MIT License for the project.
- `README.md`: this documentation.
- `pyproject.toml`: project configuration and packaging metadata (defines the `hymdall` command).
- `hymdall.py`: the tool itself.
- `sample-logs/`: example logs to try the tool on.
  - `auth-logs/`
    - `auth-1.log`: a real-world style log with several brute force attackers.
    - `auth-2.log`: a small log with no brute force.
    - `auth-3.log`: normal activity mixed with attacks.
  - `web-logs/`
    - `web-log1.log`, `web-log2.log`: web logs with scanner traffic.
    - `web-log3.log`: a log in an **unsupported** format, useful for seeing the format warning.
- `sigma-rules/`: Sigma rule files describing the detections.
  - `ssh-brute-force.yaml`: matches failed SSH password attempts.
  - `ssh-brute-force-correlation.yaml`: the "5 failures in 60 seconds" count rule.
  - `web-detection.yaml`: matches requests to suspicious web paths.
  - `correlation.yaml`: links SSH brute force and web reconnaissance from the same IP.

## Installation

**Requirements:** Python 3.8 or newer. The only dependency is `pyyaml`, which pipx installs for you automatically.

hymdall is not published on PyPI. Install it directly from the repository with pipx, which keeps the tool in an isolated environment and makes the `hymdall` command available on your PATH without touching your system Python.

### Step 1: Install pipx

| Operating System | Command |
|---|---|
| macOS | `brew install pipx` |
| Linux (Debian / Ubuntu) | `sudo apt update && sudo apt install pipx` |
| Linux (Fedora) | `sudo dnf install pipx` |
| Linux (Arch) | `sudo pacman -S pipx` |
| Windows | `winget install pipx.Pipx` (or `pip install pipx`) |

Then, on every operating system:

```bash
pipx ensurepath
```

**Restart your terminal** after running `pipx ensurepath` so the PATH changes take effect.

### Step 2: Install hymdall from the repository

```bash
pipx install git+https://github.com/D-Hamza123/hymdall.git
```

Run `pipx ensurepath` again and restart your terminal once more. You can then run the tool from anywhere:

```bash
hymdall --auth /path/to/auth.log --web /path/to/web.log
```

To pick up future updates without re-cloning:

```bash
pipx upgrade hymdall
```

### Alternative: Clone and run manually

If you prefer not to use pipx (for example, to edit the source), clone the repository, create a virtual environment and install the dependency:

```bash
git clone https://github.com/D-Hamza123/hymdall.git
cd hymdall
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install pyyaml
python3 hymdall.py --auth /path/to/auth.log --web /path/to/web.log
```

Skipping `pip install pyyaml` makes the script fail at startup with `ModuleNotFoundError: No module named 'yaml'`.

With this approach you will need to `git pull` to receive updates.

### Which option should I use?

| Option | Best for | What it does |
|---|---|---|
| **pipx install (recommended)** | Using the tool as a CLI | Installs hymdall into its own isolated environment, exposes the `hymdall` command on your PATH automatically, and lets you upgrade with `pipx upgrade hymdall` without re-cloning the repo. |
| **Clone and run manually** | Editing / contributing | Gives you direct access to the source code so you can modify `hymdall.py`. You are responsible for keeping your local copy up to date with `git pull`. |

## Usage

```bash
hymdall --auth <file> [--web <file>] [--rules <file>]
```

If you cloned the repo instead of using pipx, replace `hymdall` with `python3 hymdall.py`.

### Arguments

| Argument | Required | Description |
|---|---|---|
| `--auth <file>` | Yes | Path to an SSH auth log file (for example `/var/log/auth.log`). |
| `--web <file>` | No | Path to a web server access log. Enables web probe detection and correlation. |
| `--rules <file>` | No | Path to a Sigma rule file. Experimental, see [Sigma rules](#sigma-rules). |
| `-h`, `--help` | No | Show the help message. |

Each argument takes **one file**, not a directory. To scan several logs, run the tool once per file.

Reading system logs such as `/var/log/auth.log` usually needs `sudo`, or you can copy the file somewhere readable first.

### Examples

Scan an auth log only:
```bash
hymdall --auth sample-logs/auth-logs/auth-1.log
```

Scan an auth log and a web log, with correlation:
```bash
hymdall --auth sample-logs/auth-logs/auth-1.log --web sample-logs/web-logs/web-log1.log
```

### Sample Output

Running the second example above produces output like this (trimmed):

```text
[SSH] 185.190.58.108 (?, ?) 5 failed attempts within 60s at 2026-11-28 05:13:59
[SSH] 212.129.2.219 (?, ?) 5 failed attempts within 60s at 2026-11-28 05:48:33
...
[WEB] 198.51.100.23 accessed /wp-login.php at 2026-09-29 14:00:00+01:00
[WEB] 185.220.101.5 accessed /admin at 2026-09-29 14:00:12+01:00
...
[CORRELATED] 212.129.2.219 (?, ?): SSH brute force + web paths ['/admin']
[CORRELATED] 185.190.58.108 (?, ?): SSH brute force + web paths ['/phpmyadmin']
...
[SUMMARY] auth log: 139 lines, 129 failed logins, 6 alerts
[SUMMARY] web log: 55 lines, 55 matched, 17 suspicious hits
[WARN] 1 failed login skipped: unreadable format or invalid IP
```

What each label means:

| Label | Meaning |
|---|---|
| `[SSH]` | An IP crossed the brute force threshold. Shows its location, the number of attempts in the window, and when. |
| `[WEB]` | An IP requested a suspicious path (each path is shown once per IP). |
| `[CORRELATED]` | An IP that appears in both an `[SSH]` and a `[WEB]` alert. |
| `[SUMMARY]` | Totals for each log. |
| `[WARN]` | Lines that were skipped, or a log that does not look like the expected format. |
| `[OK]` | Nothing suspicious found for that check. |

Locations normally appear as `(Country, City)`. They show as `(?, ?)` when the lookup fails, for example when you are offline.

In a terminal, labels are color-coded.

## Supported Log Formats

**Auth log** (`--auth`): standard Linux sshd logs. hymdall looks for lines containing `Failed password ... from <IP>`, and the line must start with a timestamp in one of these forms:
- Syslog: `Nov 28 05:11:25 host sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2` (syslog has no year, so the current year is assumed)
- ISO 8601: `2026-11-28T05:11:25+00:00 host sshd[1234]: Failed password ...`

Other lines (successful logins, `Failed none`, etc.) are ignored.

**Web log** (`--web`): Apache / Nginx *common* or *combined* log format:
```text
198.51.100.23 - - [29/Sep/2026:14:00:00 +0100] "POST /wp-login.php HTTP/1.1" 403 186 "-" "Mozilla/5.0 ..."
```
Paths must match exactly: `/admin` is flagged, but `/admin/` or `/wp-login.php?redirect=x` are not.

## Privacy and network use

To show where an attacker is located, hymdall sends each IP that triggers an `[SSH]` or `[CORRELATED]` alert to the free [ip-api.com](https://ip-api.com) service. Keep in mind:
- The request is made over **plain HTTP** (the free tier does not offer HTTPS), so the IP is visible on the network.
- Only alerting IPs are sent, each IP at most once per run. IPs that only appear in `[WEB]` alerts are not looked up.
- The free tier allows about 45 lookups per minute. Lookups beyond that, or with no internet connection, show as `(?, ?)` and the scan continues normally.
- There is currently no option to turn lookups off. If your logs must not leave the machine, run the tool without network access.

## Sigma rules

The `sigma-rules/` folder describes hymdall's detections in the [Sigma](https://sigmahq.io) format, so they can be reused in other security tools.

**Current limitation:** detection in hymdall is built into the code and does **not** use these rule files yet. The `--rules` option only loads and validates a rule file. It does not change what gets detected.

`--rules` accepts only simple rules: a single `detection.selection` block, with field modifiers limited to none (exact match) or `contains`. `ssh-brute-force.yaml` and `web-detection.yaml` load fine. The correlation rules (`correlation.yaml`, `ssh-brute-force-correlation.yaml`) are not supported and make the tool exit with an "Invalid Sigma rule structure" error.

## Example Use Cases
- **System Monitoring**: check auth logs for brute force attacks.
- **Web Security**: find scanners probing for admin panels, WordPress logins or leaked `.env` files.
- **Incident Investigation**: identify IPs attacking both SSH and the web server.

## Extending the Tool
The settings you are most likely to change are in `hymdall.py`:

| What | Where | Default |
|---|---|---|
| Brute force window | `WINDOW`, top of the file | 60 seconds |
| Brute force threshold | `THRESHOLD`, top of the file | 5 attempts |
| Suspicious web paths | `suspicious_paths`, inside `main()` | `/wp-login.php`, `/admin`, `/.env`, `/phpmyadmin` |
| Auth line pattern | `ssh_pattern`, inside `main()` | `Failed password ... from <IP>` |
| Web line pattern | `web_pattern`, inside `main()` | Apache/Nginx common log format |

New timestamp formats can be added to `parse_timestamp()`.

## Contributing
Contributions are welcome! Feel free to submit issues or pull requests on the project's repository.
