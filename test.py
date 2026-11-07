# from datetime import datetime
#
# TIME_FORMATS = [
#     "%b %d %H:%M:%S", # e.g., "Jan 12 15:04:05"
#     "%Y-%m-%dT%H:%M:%S.%f%z", # e.g., "2023-01-12T15:04:05.123456+0000"
#     "%d/%b/%Y:%H:%M:%S %z", # e.g., "12/Jan/2023:15:04:05 +0000"
# ]
# def parse_timestamp(timestamp):
#     try:
#         return datetime.fromisoformat(timestamp)
#     except ValueError:
#         pass
#     for fmt in TIME_FORMATS:
#         try:
#             dt = datetime.strptime(timestamp, fmt)
#         except ValueError:
#             continue
#         if dt.year == 1900:
#             dt = dt.replace(year=datetime.now().year)
#         return dt
#     return None
#
# def get_time(line):
#     parts = line.split()
#     when = parse_timestamp(parts[0]) if parts else None
#     if when is None:
#         when = parse_timestamp(" ".join(parts[:3]))
#     return when
#
#
# print(get_time("2026-10-14T10:15:32.123456+00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"))
# print(get_time("Oct 14 10:15:32 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"))
# print(get_time("garbage"))