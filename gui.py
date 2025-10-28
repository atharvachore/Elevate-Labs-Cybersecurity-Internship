import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional

import pandas as pd
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from log_analyzer.log_parser import parse_apache_log, parse_ssh_log
from log_analyzer.detector import detect_brute_force, detect_scanning, detect_dos
from log_analyzer.blacklist_checker import check_ip_blacklist
from log_analyzer.reporter import generate_report


class LogAnalyzerGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Log Analyzer - Intrusion Detection")
        self.geometry("1100x750")

        self.project_root = os.path.dirname(os.path.abspath(__file__))
        self.visualisations_dir = os.path.join(self.project_root, 'visualisations')
        os.makedirs(self.visualisations_dir, exist_ok=True)

        self.df: Optional[pd.DataFrame] = None
        self.incidents = []

        self._build_controls()
        self._build_charts()
        self._build_table()

    def _build_controls(self) -> None:
        controls = ttk.Frame(self)
        controls.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

        # File picker
        ttk.Label(controls, text="Log file:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.log_path_var = tk.StringVar()
        self.log_entry = ttk.Entry(controls, textvariable=self.log_path_var, width=70)
        self.log_entry.grid(row=0, column=1, padx=5)
        ttk.Button(controls, text="Browse", command=self._choose_file).grid(row=0, column=2, padx=5)

        # Log type
        ttk.Label(controls, text="Log type:").grid(row=0, column=3, sticky=tk.W, padx=5)
        self.log_type_var = tk.StringVar(value="auto")
        ttk.Combobox(controls, textvariable=self.log_type_var, values=["auto", "apache", "ssh"], width=10, state="readonly").grid(row=0, column=4, padx=5)

        # Thresholds
        ttk.Label(controls, text="Brute threshold:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.brute_thr_var = tk.IntVar(value=10)
        ttk.Entry(controls, textvariable=self.brute_thr_var, width=8).grid(row=1, column=1, sticky=tk.W)

        ttk.Label(controls, text="Scan threshold:").grid(row=1, column=2, sticky=tk.W, padx=5)
        self.scan_thr_var = tk.IntVar(value=100)
        ttk.Entry(controls, textvariable=self.scan_thr_var, width=8).grid(row=1, column=3, sticky=tk.W)

        ttk.Label(controls, text="DoS window(s):").grid(row=1, column=4, sticky=tk.W, padx=5)
        self.dos_window_var = tk.IntVar(value=60)
        ttk.Entry(controls, textvariable=self.dos_window_var, width=8).grid(row=1, column=5, sticky=tk.W)

        ttk.Label(controls, text="DoS threshold:").grid(row=1, column=6, sticky=tk.W, padx=5)
        self.dos_thr_var = tk.IntVar(value=500)
        ttk.Entry(controls, textvariable=self.dos_thr_var, width=8).grid(row=1, column=7, sticky=tk.W)

        # Actions
        ttk.Button(controls, text="Analyze", command=self._on_analyze).grid(row=0, column=5, padx=10)
        ttk.Button(controls, text="Open Reports", command=self._open_reports).grid(row=0, column=6, padx=5)
        ttk.Button(controls, text="Open Charts", command=self._open_visualisations).grid(row=0, column=7, padx=5)

        # Status
        self.status_var = tk.StringVar(value="Choose a log file and click Analyze")
        self.progress = ttk.Progressbar(controls, mode="determinate", length=250)
        self.progress.grid(row=2, column=0, columnspan=4, sticky=tk.W, pady=(10, 0))
        ttk.Label(controls, textvariable=self.status_var).grid(row=2, column=4, columnspan=4, sticky=tk.W)

    def _build_charts(self) -> None:
        charts = ttk.Frame(self)
        charts.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Two chart areas (Top IPs and Hourly Activity)
        self.fig = Figure(figsize=(8, 4), dpi=100)
        self.ax1 = self.fig.add_subplot(121)
        self.ax2 = self.fig.add_subplot(122)
        self.fig.tight_layout()
        self.canvas = FigureCanvasTkAgg(self.fig, master=charts)
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    def _build_table(self) -> None:
        table_frame = ttk.Frame(self)
        table_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=10, pady=10)

        columns = ("type", "source_ip", "user", "count", "timestamp", "blacklisted")
        self.tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=10)
        for col in columns:
            self.tree.heading(col, text=col.title())
            self.tree.column(col, width=150, anchor=tk.W)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Tag style for blacklisted rows
        self.tree.tag_configure('blacklisted', background='#ffe6e6')

    def _choose_file(self) -> None:
        path = filedialog.askopenfilename(title="Select log file", filetypes=[("Log files", "*.log *.logs *.*")])
        if path:
            self.log_path_var.set(path)
            if self.log_type_var.get() == "auto":
                inferred = self._infer_log_type(path)
                if inferred:
                    self.log_type_var.set(inferred)

    def _infer_log_type(self, path: str) -> Optional[str]:
        try:
            with open(path, 'r', errors='ignore') as f:
                sample = ''.join([next(f) for _ in range(10)])
        except Exception:
            return None
        if 'sshd[' in sample or 'Failed password' in sample or 'Accepted password' in sample:
            return 'ssh'
        # Very rough Apache access log check
        if '/' in sample and 'HTTP/' in sample:
            return 'apache'
        return None

    def _on_analyze(self) -> None:
        log_file = self.log_path_var.get().strip()
        if not log_file or not os.path.exists(log_file):
            messagebox.showerror("Missing file", "Please choose a valid log file")
            return

        log_type = self.log_type_var.get()
        if log_type == 'auto':
            inferred = self._infer_log_type(log_file)
            if not inferred:
                messagebox.showerror("Log type", "Could not infer log type. Please select one.")
                return
            log_type = inferred
            self.log_type_var.set(log_type)

        try:
            self._set_status("Parsing log…", 10)
            if log_type == 'apache':
                df = parse_apache_log(log_file)
            else:
                df = parse_ssh_log(log_file)

            if df.empty:
                self._set_status("No data parsed.", 0)
                messagebox.showinfo("No Data", "No entries parsed from the selected file.")
                return

            self.df = df

            # Threat detection
            self._set_status("Detecting threats…", 35)
            incidents = []
            brute = detect_brute_force(df, log_type, threshold=self.brute_thr_var.get())
            if not brute.empty:
                incidents.append(("Brute-Force", brute))

            scan = detect_scanning(df, threshold=self.scan_thr_var.get())
            if not scan.empty:
                incidents.append(("Scanning", scan))

            dos = detect_dos(df, time_window=self.dos_window_var.get(), threshold=self.dos_thr_var.get())
            if not dos.empty:
                incidents.append(("DoS", dos))

            # Blacklist annotate
            self._set_status("Checking blacklist…", 55)
            for _, inc_df in incidents:
                if 'source_ip' in inc_df.columns:
                    inc_df['is_blacklisted'] = inc_df['source_ip'].apply(check_ip_blacklist)

            self.incidents = incidents

            # Visualize
            self._set_status("Rendering charts…", 70)
            self._render_charts(df)

            # Table
            self._set_status("Populating incidents…", 85)
            self._populate_table(incidents)

            # Report
            self._set_status("Generating report…", 95)
            report_path = generate_report(incidents)

            self._set_status(f"Done. Report saved to: {report_path}", 100)
        except Exception as exc:
            self._set_status("Error during analysis", 0)
            messagebox.showerror("Error", str(exc))

    def _render_charts(self, df: pd.DataFrame) -> None:
        self.ax1.clear()
        self.ax2.clear()

        if 'source_ip' in df.columns:
            ip_counts = df['source_ip'].value_counts().head(10)
            self.ax1.bar(ip_counts.index.astype(str), ip_counts.values)
            self.ax1.set_title('Top 10 IPs by Requests')
            self.ax1.set_xticklabels(ip_counts.index.astype(str), rotation=45, ha='right')

        if 'timestamp' in df.columns:
            dt = pd.to_datetime(df['timestamp'], errors='coerce')
            hours = dt.dt.hour.dropna()
            hour_counts = hours.value_counts().sort_index()
            self.ax2.plot(hour_counts.index, hour_counts.values, marker='o')
            self.ax2.set_title('Requests by Hour')
            self.ax2.set_xticks(range(0, 24, 2))

        self.fig.tight_layout()
        self.canvas.draw()

        # Also save static charts to visualisations folder
        self.fig.savefig(os.path.join(self.visualisations_dir, 'gui_latest.png'), bbox_inches='tight')

    def _populate_table(self, incidents) -> None:
        for row in self.tree.get_children():
            self.tree.delete(row)

        for inc_type, inc_df in incidents:
            display_df = inc_df.copy()
            if 'timestamp' not in display_df.columns:
                display_df['timestamp'] = ''
            if 'user' not in display_df.columns:
                display_df['user'] = ''
            if 'count' not in display_df.columns:
                # value_counts may produce '0' index value name
                if 'source_ip' in display_df.columns and display_df.shape[1] == 2:
                    # Already normalized in detectors; else best-effort
                    pass
                else:
                    display_df['count'] = ''
            if 'is_blacklisted' not in display_df.columns and 'source_ip' in display_df.columns:
                display_df['is_blacklisted'] = display_df['source_ip'].apply(check_ip_blacklist)

            for _, row in display_df.iterrows():
                is_blk = bool(row.get('is_blacklisted', False))
                values = (
                    inc_type,
                    row.get('source_ip', ''),
                    row.get('user', ''),
                    row.get('count', ''),
                    row.get('timestamp', ''),
                    'Yes' if is_blk else 'No'
                )
                tags = ('blacklisted',) if is_blk else ()
                self.tree.insert('', tk.END, values=values, tags=tags)

    def _open_reports(self) -> None:
        path = os.path.join(self.project_root, 'Reports')
        os.makedirs(path, exist_ok=True)
        self._open_in_os(path)

    def _open_visualisations(self) -> None:
        os.makedirs(self.visualisations_dir, exist_ok=True)
        self._open_in_os(self.visualisations_dir)

    def _open_in_os(self, path: str) -> None:
        try:
            # macOS
            os.system(f"open '{path}'")
        except Exception:
            messagebox.showinfo("Open", f"Folder: {path}")

    def _set_status(self, text: str, progress: int) -> None:
        self.status_var.set(text)
        self.progress['value'] = progress
        self.update_idletasks()


def launch() -> None:
    app = LogAnalyzerGUI()
    app.mainloop()


if __name__ == '__main__':
    launch()


