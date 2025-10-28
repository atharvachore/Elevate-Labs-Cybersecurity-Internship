import datetime
import os

def generate_report(incidents):
    """
    Generates a text-based incident report.
    """
    # Ensure correct case-sensitive output directory `Reports/`
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(project_root, 'Reports')
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(reports_dir, f'incident_report_{timestamp}.txt')
    
    with open(report_path, 'w') as f:
        f.write("=== Log Analysis Incident Report ===\n")
        f.write(f"Report Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        if not incidents:
            f.write("No suspicious patterns detected.\n")
            return report_path
            
        for incident_type, incident_df in incidents:
            f.write(f"--- Detected Threat: {incident_type} ---\n")
            
            if incident_df.empty:
                f.write("No incidents of this type found.\n\n")
                continue
                
            f.write(f"Total incidents: {len(incident_df)}\n")
            
            # If the DataFrame has a column for blacklisting, report on it
            if 'is_blacklisted' in incident_df.columns:
                blacklisted_count = incident_df['is_blacklisted'].sum()
                f.write(f"Blacklisted IPs in this category: {blacklisted_count}\n")
            
            f.write("\nDetails:\n")
            f.write(incident_df.to_string())
            f.write("\n\n")
            
    return report_path