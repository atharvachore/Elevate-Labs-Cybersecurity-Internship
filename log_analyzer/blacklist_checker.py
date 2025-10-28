def check_ip_blacklist(ip):
    """
    Checks if an IP address exists in the public IP blacklist file.
    """
    try:
        # Use correct case-sensitive path and absolute resolution
        import os
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        blacklist_path = os.path.join(project_root, 'Data', 'ip_blacklist.txt')
        with open(blacklist_path, 'r') as f:
            blacklist = {line.strip() for line in f}
            return ip in blacklist
    except FileNotFoundError:
        print("IP blacklist file not found. Skipping blacklist check.")
        return False