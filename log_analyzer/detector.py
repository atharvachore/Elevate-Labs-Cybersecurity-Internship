import pandas as pd

def detect_brute_force(df, log_type, threshold=10):
    """
    Detects brute-force attempts based on multiple failed logins or requests.
    """
    if log_type == "apache":
        # Look for multiple 401 (unauthorized) status codes from a single IP
        if 'status' not in df.columns or 'source_ip' not in df.columns:
            return pd.DataFrame()
        unauthorized_requests = df[df['status'] == '401']
        brute_force_ips = unauthorized_requests['source_ip'].value_counts()
        if brute_force_ips.empty:
            return pd.DataFrame()
        result = brute_force_ips[brute_force_ips > threshold].reset_index()
        result.columns = ['source_ip', 'count']
        return result
    
    elif log_type == "ssh":
        # Look for multiple "Failed password" attempts from a single IP/user combo
        if 'message' not in df.columns or 'source_ip' not in df.columns or 'user' not in df.columns:
            return pd.DataFrame()
        failed_logins = df[df['message'].str.contains("Failed password", na=False)]
        if failed_logins.empty:
            return pd.DataFrame()
        brute_force_attempts = failed_logins.groupby(['source_ip', 'user']).size().reset_index(name='count')
        return brute_force_attempts[brute_force_attempts['count'] > threshold]

def detect_scanning(df, threshold=100):
    """
    Detects port or vulnerability scanning by an IP.
    """
    if 'request' not in df.columns or 'source_ip' not in df.columns:
        return pd.DataFrame() # Not applicable for all log types
    
    # Identify IPs making an unusually high number of requests
    ip_counts = df['source_ip'].value_counts()
    if ip_counts.empty:
        return pd.DataFrame()
    scanning_ips = ip_counts[ip_counts > threshold].reset_index()
    scanning_ips.columns = ['source_ip', 'count']
    return scanning_ips

def detect_dos(df, time_window=60, threshold=500):
    """
    Detects Denial-of-Service (DoS) attacks by looking for a high volume of requests
    from a single IP in a short time window.
    """
    if 'timestamp' not in df.columns or 'source_ip' not in df.columns:
        return pd.DataFrame()
    
    # Coerce parsing errors and drop invalid timestamps
    df = df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df = df.dropna(subset=['timestamp'])
    if df.empty:
        return pd.DataFrame()
    
    # Group by IP and count requests within a sliding time window
    dos_incidents = []
    for ip, group in df.groupby('source_ip'):
        group = group.sort_values('timestamp')
        start_time = group['timestamp'].iloc[0]
        for i in range(len(group)):
            end_time = group['timestamp'].iloc[i]
            # Check for a high request count in the last `time_window` seconds
            requests_in_window = group[(group['timestamp'] >= end_time - pd.Timedelta(seconds=time_window)) & (group['timestamp'] <= end_time)]
            if len(requests_in_window) > threshold:
                dos_incidents.append({'source_ip': ip, 'count': len(requests_in_window), 'timestamp': end_time})
                break # Move to the next IP once a DoS is detected
                
    if not dos_incidents:
        return pd.DataFrame()
        
    return pd.DataFrame(dos_incidents)