import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime, timedelta
import re
from collections import Counter
import random
import os

class CybersecurityDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Advanced Cybersecurity Analyzer")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        self.setup_gui()
        self.analyzer = AttackAnalyzer()
        self.current_log_file = None
        
    def setup_gui(self):
        # Header
        header_frame = tk.Frame(self.root, bg='#34495e', height=80)
        header_frame.pack(fill='x', padx=10, pady=10)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(header_frame, text="🛡️ CYBERSECURITY ATTACK DASHBOARD", 
                              font=('Arial', 20, 'bold'), fg='white', bg='#34495e')
        title_label.pack(pady=20)
        
        # Metrics Frame
        metrics_frame = tk.Frame(self.root, bg='#2c3e50')
        metrics_frame.pack(fill='x', padx=10, pady=5)
        
        self.metric_vars = {}
        metric_names = ['Total Attacks', 'Unique IPs', 'High Severity', 'Time Span']
        for i, name in enumerate(metric_names):
            frame = tk.Frame(metrics_frame, bg='#34495e', relief='raised', bd=2)
            frame.grid(row=0, column=i, padx=5, pady=5, sticky='ew')
            metrics_frame.columnconfigure(i, weight=1)
            
            label = tk.Label(frame, text=name, font=('Arial', 10), fg='white', bg='#34495e')
            label.pack()
            
            var = tk.StringVar(value="0")
            value_label = tk.Label(frame, textvariable=var, font=('Arial', 16, 'bold'), 
                                  fg='#e74c3c', bg='#34495e')
            value_label.pack()
            self.metric_vars[name] = var
        
        # Controls Frame
        controls_frame = tk.Frame(self.root, bg='#2c3e50')
        controls_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Button(controls_frame, text="📁 Load Log File", command=self.load_log_file,
                 font=('Arial', 12), bg='#3498db', fg='white').pack(side='left', padx=5)
        tk.Button(controls_frame, text="📊 Generate Sample Data", command=self.generate_data,
                 font=('Arial', 12), bg='#9b59b6', fg='white').pack(side='left', padx=5)
        tk.Button(controls_frame, text="🔄 Analyze Attacks", command=self.analyze_attacks,
                 font=('Arial', 12), bg='#2ecc71', fg='white').pack(side='left', padx=5)
        tk.Button(controls_frame, text="📈 Show Charts", command=self.show_charts,
                 font=('Arial', 12), bg='#e67e22', fg='white').pack(side='left', padx=5)
        tk.Button(controls_frame, text="📄 Generate Report", command=self.generate_report,
                 font=('Arial', 12), bg='#1abc9c', fg='white').pack(side='left', padx=5)
        
        # File Info Frame
        self.file_info_frame = tk.Frame(self.root, bg='#2c3e50')
        self.file_info_frame.pack(fill='x', padx=10, pady=5)
        
        self.file_label = tk.Label(self.file_info_frame, text="No log file loaded", 
                                  font=('Arial', 10), fg='white', bg='#2c3e50')
        self.file_label.pack()
        
        # Main Content
        content_frame = tk.Frame(self.root, bg='#2c3e50')
        content_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left - Attack Log
        left_frame = tk.Frame(content_frame, bg='#34495e')
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 5))
        
        tk.Label(left_frame, text="🚨 RECENT ATTACKS", font=('Arial', 14, 'bold'), 
                fg='white', bg='#34495e').pack(pady=5)
        
        self.attack_tree = ttk.Treeview(left_frame, columns=('Time', 'IP', 'Type', 'Severity', 'Data'), show='headings')
        self.attack_tree.heading('Time', text='Time')
        self.attack_tree.heading('IP', text='IP Address')
        self.attack_tree.heading('Type', text='Attack Type')
        self.attack_tree.heading('Severity', text='Severity')
        self.attack_tree.heading('Data', text='Attack Data')
        
        self.attack_tree.column('Time', width=150)
        self.attack_tree.column('IP', width=120)
        self.attack_tree.column('Type', width=120)
        self.attack_tree.column('Severity', width=80)
        self.attack_tree.column('Data', width=200)
        
        # Add scrollbar to treeview
        tree_scroll = ttk.Scrollbar(left_frame, orient='vertical', command=self.attack_tree.yview)
        self.attack_tree.configure(yscrollcommand=tree_scroll.set)
        self.attack_tree.pack(side='left', fill='both', expand=True, padx=(10, 0), pady=10)
        tree_scroll.pack(side='right', fill='y', padx=(0, 10), pady=10)
        
        # Right - Charts Frame
        self.chart_frame = tk.Frame(content_frame, bg='#34495e')
        self.chart_frame.pack(side='right', fill='both', expand=True, padx=(5, 0))
        
    def load_log_file(self):
        """Open file dialog to select honeypot log file"""
        file_path = filedialog.askopenfilename(
            title="Select Honeypot Log File",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            self.current_log_file = file_path
            self.file_label.config(text=f"📁 Loaded: {os.path.basename(file_path)}")
            messagebox.showinfo("Success", f"✅ Loaded log file: {file_path}")
    
    def generate_data(self):
        """Generate impressive sample attack data"""
        countries = ['United States', 'China', 'Russia', 'Brazil', 'India', 'Germany', 'France', 'UK', 'Japan', 'South Korea']
        attack_types = ['SSH Brute Force', 'Port Scanning', 'Malware Delivery', 'Vulnerability Probe', 'DDoS Attack']
        severities = ['Low', 'Medium', 'High']
        
        sample_data = []
        for i in range(100):
            timestamp = datetime.now() - timedelta(hours=random.randint(0, 168))
            ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
            attack_type = random.choice(attack_types)
            severity = random.choices(severities, weights=[4, 3, 2])[0]
            country = random.choice(countries)
            
            sample_data.append(f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] SSH attack from {ip}:2222 - Data: {attack_type} from {country} - Severity: {severity}\n")
        
        # Save to current directory
        self.current_log_file = 'honeypot.log'
        with open(self.current_log_file, 'w') as f:
            f.writelines(sample_data)
        
        self.file_label.config(text=f"📁 Generated: {os.path.basename(self.current_log_file)}")
        messagebox.showinfo("Success", "✅ Generated 100 sophisticated attack samples from 10 countries!")
    
    def analyze_attacks(self):
        """Analyze the attack data from loaded log file"""
        if not self.current_log_file:
            messagebox.showerror("Error", "❌ No log file loaded. Please load a file or generate sample data.")
            return
        
        try:
            self.analyzer.parse_logs(self.current_log_file)
            
            if not self.analyzer.attacks:
                messagebox.showerror("Error", "❌ No valid attack data found in the log file.")
                return
            
            # Update metrics
            self.metric_vars['Total Attacks'].set(len(self.analyzer.attacks))
            self.metric_vars['Unique IPs'].set(len(set(a['ip'] for a in self.analyzer.attacks)))
            
            high_severity = len([a for a in self.analyzer.attacks if a.get('severity', 'Low') == 'High'])
            self.metric_vars['High Severity'].set(high_severity)
            
            # Calculate time span
            if self.analyzer.attacks:
                times = [a['timestamp'] for a in self.analyzer.attacks]
                time_span = (max(times) - min(times))
                self.metric_vars['Time Span'].set(f"{time_span.days}d {time_span.seconds//3600}h")
            
            # Update attack list
            for item in self.attack_tree.get_children():
                self.attack_tree.delete(item)
            
            for attack in sorted(self.analyzer.attacks, key=lambda x: x['timestamp'], reverse=True)[:50]:
                self.attack_tree.insert('', 'end', values=(
                    attack['timestamp'].strftime('%m/%d %H:%M:%S'),
                    attack['ip'],
                    attack.get('type', 'Unknown'),
                    attack.get('severity', 'Low'),
                    attack.get('data', '')[:30] + '...' if len(attack.get('data', '')) > 30 else attack.get('data', '')
                ))
            
            messagebox.showinfo("Analysis Complete", f"📊 Analyzed {len(self.analyzer.attacks)} attacks successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"❌ Failed to analyze log file: {str(e)}")
    
    def show_charts(self):
        """Display attack analysis charts"""
        if not self.analyzer.attacks:
            messagebox.showerror("Error", "No data to visualize. Analyze attacks first.")
            return
        
        # Clear previous charts
        for widget in self.chart_frame.winfo_children():
            widget.destroy()
        
        tk.Label(self.chart_frame, text="📊 ATTACK ANALYTICS", font=('Arial', 14, 'bold'), 
                fg='white', bg='#34495e').pack(pady=5)
        
        # Create charts
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(10, 8))
        fig.patch.set_facecolor('#34495e')
        
        df = pd.DataFrame(self.analyzer.attacks)
        
        # Chart 1: Attack types
        attack_counts = df['type'].value_counts()
        colors = plt.cm.Set3(range(len(attack_counts)))
        ax1.pie(attack_counts.values, labels=attack_counts.index, autopct='%1.1f%%', 
                startangle=90, colors=colors)
        ax1.set_title('Attack Type Distribution', color='white', fontweight='bold')
        
        # Chart 2: Severity levels
        severity_counts = df['severity'].value_counts()
        colors = ['#2ecc71', '#f39c12', '#e74c3c']  # Green, Orange, Red
        ax2.bar(severity_counts.index, severity_counts.values, color=colors)
        ax2.set_title('Attack Severity Levels', color='white', fontweight='bold')
        ax2.tick_params(axis='x', rotation=45, colors='white')
        ax2.tick_params(axis='y', colors='white')
        
        # Chart 3: Timeline
        df['hour'] = df['timestamp'].dt.floor('h')
        timeline = df.groupby('hour').size()
        ax3.plot(timeline.index, timeline.values, marker='o', color='#e74c3c', linewidth=2, markersize=4)
        ax3.fill_between(timeline.index, timeline.values, alpha=0.3, color='#e74c3c')
        ax3.set_title('Attack Timeline', color='white', fontweight='bold')
        ax3.tick_params(axis='x', rotation=45, colors='white')
        ax3.tick_params(axis='y', colors='white')
        ax3.grid(True, alpha=0.3)
        
        # Chart 4: Top attackers
        top_ips = df['ip'].value_counts().head(8)
        ax4.barh(range(len(top_ips)), top_ips.values, color='#3498db')
        ax4.set_yticks(range(len(top_ips)))
        ax4.set_yticklabels(top_ips.index, fontsize=8)
        ax4.set_title('Top Attackers by IP', color='white', fontweight='bold')
        ax4.tick_params(axis='x', colors='white')
        ax4.tick_params(axis='y', colors='white')
        
        # Set background color for all axes
        for ax in [ax1, ax2, ax3, ax4]:
            ax.set_facecolor('#2c3e50')
        
        plt.tight_layout()
        
        # Embed in Tkinter
        canvas = FigureCanvasTkAgg(fig, self.chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)
    
    def generate_report(self):
        """Generate professional report"""
        if not self.analyzer.attacks:
            messagebox.showerror("Error", "No data for report. Analyze attacks first.")
            return
        
        # Create detailed report
        df = pd.DataFrame(self.analyzer.attacks)
        
        report_data = {
            'Total Attacks': len(self.analyzer.attacks),
            'Unique Attackers': len(set(a['ip'] for a in self.analyzer.attacks)),
            'Time Period': f"{(max(a['timestamp'] for a in self.analyzer.attacks) - min(a['timestamp'] for a in self.analyzer.attacks)).days} days",
            'Most Common Attack': df['type'].mode().iloc[0] if not df.empty else 'None',
            'High Severity Attacks': len(df[df['severity'] == 'High']),
            'Analysis Date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        report_text = "🛡️ CYBERSECURITY THREAT INTELLIGENCE REPORT\n" + "="*50 + "\n\n"
        for key, value in report_data.items():
            report_text += f"• {key}: {value}\n"
        
        report_text += "\n🔍 TOP THREAT INDICATORS:\n"
        top_attackers = df['ip'].value_counts().head(5)
        for ip, count in top_attackers.items():
            report_text += f"   - {ip}: {count} attacks\n"
        
        report_text += f"\n📊 Generated by Advanced Cybersecurity Analyzer\n"
        report_text += f"   File: {os.path.basename(self.current_log_file) if self.current_log_file else 'Unknown'}"
        
        # Show in scrollable text window
        report_window = tk.Toplevel(self.root)
        report_window.title("Threat Intelligence Report")
        report_window.geometry("600x400")
        report_window.configure(bg='#2c3e50')
        
        text_widget = tk.Text(report_window, wrap='word', font=('Courier', 10), 
                             bg='#1a1a1a', fg='#00ff00', padx=10, pady=10)
        text_widget.insert('1.0', report_text)
        text_widget.config(state='disabled')
        
        scrollbar = ttk.Scrollbar(report_window, orient='vertical', command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.pack(side='left', fill='both', expand=True, padx=10, pady=10)
        scrollbar.pack(side='right', fill='y', pady=10)

class AttackAnalyzer:
    def __init__(self):
        self.attacks = []
    
    def parse_logs(self, log_file):
        """Parse real honeypot logs with multiple format support"""
        self.attacks = []
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Try multiple log formats
                    attack = self.parse_log_line(line)
                    if attack:
                        self.attacks.append(attack)
                    
        except Exception as e:
            raise Exception(f"Error reading log file: {str(e)}")
    
    def parse_log_line(self, line):
        """Parse different honeypot log formats"""
        # Format 1: [timestamp] SSH attack from IP:port - Data: ...
        match1 = re.search(r'\[(.*?)\] SSH attack from ([\d.]+):(\d+) - Data: (.*)', line)
        if match1:
            timestamp, ip, port, data = match1.groups()
            return {
                'timestamp': datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S'),
                'ip': ip,
                'port': port,
                'data': data,
                'type': self.classify_attack(data),
                'severity': self.assess_severity(data)
            }
        
        # Format 2: Custom format with severity
        match2 = re.search(r'\[(.*?)\] SSH attack from ([\d.]+):(\d+) - Data: (.*?) from (.*?) - Severity: (.*)', line)
        if match2:
            timestamp, ip, port, attack_type, country, severity = match2.groups()
            return {
                'timestamp': datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S'),
                'ip': ip,
                'type': attack_type,
                'country': country,
                'severity': severity,
                'data': f"{attack_type} from {country}"
            }
        
        # Format 3: Simple connection logs
        match3 = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?([\d.]+).*?(connected|connection)', line, re.IGNORECASE)
        if match3:
            timestamp, ip, _ = match3.groups()
            return {
                'timestamp': datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S'),
                'ip': ip,
                'type': 'Connection Attempt',
                'severity': 'Low',
                'data': 'Initial connection'
            }
        
        return None
    
    def classify_attack(self, data):
        """Classify attack type based on log data"""
        data_lower = data.lower()
        
        if any(x in data_lower for x in ['brute', 'password', 'login', 'admin', 'root']):
            return 'Brute Force'
        elif any(x in data_lower for x in ['scan', 'port', 'recon']):
            return 'Port Scanning'
        elif any(x in data_lower for x in ['malware', 'payload', 'exploit']):
            return 'Malware Delivery'
        elif any(x in data_lower for x in ['vulnerability', 'exploit']):
            return 'Vulnerability Probe'
        elif 'connection established' in data_lower:
            return 'Initial Connection'
        else:
            return 'Reconnaissance'
    
    def assess_severity(self, data):
        """Assess attack severity"""
        data_lower = data.lower()
        
        if any(x in data_lower for x in ['malware', 'exploit', 'root', 'admin']):
            return 'High'
        elif any(x in data_lower for x in ['brute', 'password', 'scan']):
            return 'Medium'
        else:
            return 'Low'

if __name__ == "__main__":
    root = tk.Tk()
    app = CybersecurityDashboard(root)
    root.mainloop()