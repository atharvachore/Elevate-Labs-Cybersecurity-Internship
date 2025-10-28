# main.py
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import re
import os
from log_analyzer.log_parser import parse_apache_log, parse_ssh_log
from log_analyzer.detector import detect_brute_force, detect_scanning, detect_dos
from log_analyzer.blacklist_checker import check_ip_blacklist
from log_analyzer.reporter import generate_report

def main():
    parser = argparse.ArgumentParser(description="Log File Analyzer for Intrusion Detection")
    parser.add_argument("--log_file", required=False, default=None, help="Path to the log file (Apache or SSH).")
    parser.add_argument("--log_type", required=False, default=None, choices=["apache", "ssh"], help="Type of log file.")
    parser.add_argument("--gui", action="store_true", help="Launch the graphical user interface.")

    args = parser.parse_args()

    # Resolve defaults if args are not provided
    project_root = os.path.dirname(os.path.abspath(__file__))
    if not args.log_file or not args.log_type:
        default_log = os.path.join(project_root, 'Logs', 'apache.logs')
        if os.path.exists(default_log):
            if not args.log_file:
                args.log_file = default_log
            if not args.log_type:
                args.log_type = 'apache'
            print(f"No arguments provided. Using defaults: log_file={args.log_file}, log_type={args.log_type}")
        else:
            print("Error: --log_file and --log_type are required, or place a default log at 'Logs/apache.logs'.")
            print("Example: python main.py --log_file Logs/apache.logs --log_type apache")
            return

    # Launch GUI if requested
    if args.gui:
        from gui import launch
        launch()
        return

    # Parse logs
    print(f"Parsing {args.log_type} log file: {args.log_file}...")
    if args.log_type == "apache":
        df = parse_apache_log(args.log_file)
    elif args.log_type == "ssh":
        df = parse_ssh_log(args.log_file)
    else:
        print("Invalid log type.")
        return

    if df.empty:
        print("No data parsed from the log file.")
        return

    # Threat Detection
    print("Detecting threats...")
    incidents = []
    
    brute_force_incidents = detect_brute_force(df, args.log_type)
    if not brute_force_incidents.empty:
        incidents.append(("Brute-Force", brute_force_incidents))
    
    scanning_incidents = detect_scanning(df)
    if not scanning_incidents.empty:
        incidents.append(("Scanning", scanning_incidents))
        
    dos_incidents = detect_dos(df)
    if not dos_incidents.empty:
        incidents.append(("DoS", dos_incidents))

    # IP Blacklist Check
    print("Checking against IP blacklist...")
    for incident_type, incident_df in incidents:
        incident_df['is_blacklisted'] = incident_df['source_ip'].apply(check_ip_blacklist)

    # Visualization
    print("Generating visualizations...")
    # Ensure visualisations directory exists (correct case)
    project_root = os.path.dirname(os.path.abspath(__file__))
    vis_dir = os.path.join(project_root, 'visualisations')
    if not os.path.exists(vis_dir):
        os.makedirs(vis_dir)
    if 'source_ip' in df.columns:
        ip_counts = df['source_ip'].value_counts().head(20)
        plt.figure(figsize=(12, 6))
        ip_counts.plot(kind='bar')
        plt.title('Top 20 IP Addresses by Request Count')
        plt.xlabel('IP Address')
        plt.ylabel('Request Count')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig(os.path.join(vis_dir, 'top_ips.png'))
        plt.close()
    
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df['hour'] = df['timestamp'].dt.hour
        hourly_counts = df.groupby('hour').size()
        plt.figure(figsize=(12, 6))
        hourly_counts.plot(kind='line', marker='o')
        plt.title('Requests by Hour of Day')
        plt.xlabel('Hour of Day')
        plt.ylabel('Request Count')
        plt.xticks(range(24))
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(os.path.join(vis_dir, 'hourly_access.png'))
        plt.close()

    # Generate Report
    print("Generating incident report...")
    report_path = generate_report(incidents)
    print(f"Analysis complete. Report exported to: {report_path}")

if __name__ == "__main__":
    main()