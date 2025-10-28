import pandas as pd
import re

def parse_apache_log(log_file_path):
    """
    Parses an Apache access log file.
    """
    apache_log_regex = re.compile(
        r'(?P<source_ip>\S+)\s+'
        r'(?P<identity>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<request>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<size>\S+)\s*'
    )
    data = []
    with open(log_file_path, 'r', errors='ignore') as f:
        for line in f:
            match = apache_log_regex.match(line)
            if match:
                data.append(match.groupdict())
    df = pd.DataFrame(data)
    if 'timestamp' in df.columns:
        # Apache format example: 15/Oct/2025:10:00:01 +0530
        df['timestamp'] = pd.to_datetime(
            df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce'
        )
    return df

def parse_ssh_log(log_file_path):
    """
    Parses an SSH authentication log file.
    """
    ssh_log_regex = re.compile(
        r'^(?P<timestamp>\S+\s+\S+\s+\S+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'sshd\[\S+\]:\s+'
        r'(?P<message>.*)'
    )
    data = []
    with open(log_file_path, 'r', errors='ignore') as f:
        for line in f:
            match = ssh_log_regex.match(line)
            if match:
                entry = match.groupdict()
                
                # Extract source_ip and user from the message
                if "Failed password for" in entry['message']:
                    ip_match = re.search(r'from\s+(\S+)\s+port', entry['message'])
                    user_match = re.search(r'for\s+(\S+)\s+from', entry['message'])
                    if ip_match and user_match:
                        entry['source_ip'] = ip_match.group(1)
                        entry['user'] = user_match.group(1)
                        data.append(entry)
                elif "Accepted password for" in entry['message']:
                    ip_match = re.search(r'from\s+(\S+)\s+port', entry['message'])
                    user_match = re.search(r'for\s+(\S+)\s+from', entry['message'])
                    if ip_match and user_match:
                        entry['source_ip'] = ip_match.group(1)
                        entry['user'] = user_match.group(1)
                        data.append(entry)
    
    df = pd.DataFrame(data)
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='%b %d %H:%M:%S', errors='coerce').apply(lambda x: x.replace(year=2025))
    return df