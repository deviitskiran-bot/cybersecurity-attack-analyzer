#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import re
import json
from collections import Counter
import os

class AttackChainAnalyzer:
    def __init__(self):
        self.attacks = []
        self.timeline = []
        
    def parse_honeypot_log(self, log_file):
        """Parse honeypot log file and extract attack data"""
        print("🔍 Analyzing honeypot logs...")
        
        attacks = []
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                # Parse log line format: [timestamp] SSH attack from IP:port - Data: ...
                match = re.search(r'\[(.*?)\] SSH attack from ([\d.]+):(\d+) - Data: (.*)', line)
                if match:
                    timestamp, ip, port, data = match.groups()
                    attacks.append({
                        'timestamp': datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S'),
                        'ip': ip,
                        'port': port,
                        'data': data,
                        'type': self.classify_attack(data)
                    })
        
        self.attacks = attacks
        print(f"📊 Found {len(attacks)} attack events")
        return attacks
    
    def classify_attack(self, data):
        """Classify the type of attack based on the data"""
        data_lower = data.lower()
        
        if 'connection established' in data_lower:
            return 'Initial Connection'
        elif 'ssh' in data_lower and 'key' in data_lower:
            return 'Key Exchange'
        elif any(x in data_lower for x in ['admin', 'root', 'password', 'login']):
            return 'Brute Force'
        elif len(data) > 50:
            return 'Payload Delivery'
        elif 'connection closed' in data_lower:
            return 'Connection Closed'
        else:
            return 'Reconnaissance'
    
    def generate_timeline(self):
        """Generate chronological attack timeline"""
        if not self.attacks:
            return []
            
        timeline = sorted(self.attacks, key=lambda x: x['timestamp'])
        self.timeline = timeline
        return timeline
    
    def detect_attack_patterns(self):
        """Detect common attack patterns"""
        patterns = {
            'port_scanning': [],
            'brute_force': [],
            'distributed_attacks': []
        }
        
        # Count attacks per IP
        ip_counts = Counter(attack['ip'] for attack in self.attacks)
        
        # Detect port scanning (multiple ports from same IP)
        for ip, count in ip_counts.items():
            if count > 5:
                patterns['port_scanning'].append(ip)
        
        # Detect brute force (many authentication attempts)
        brute_force_ips = [attack['ip'] for attack in self.attacks 
                          if attack['type'] == 'Brute Force']
        brute_counts = Counter(brute_force_ips)
        patterns['brute_force'] = [ip for ip, count in brute_counts.items() if count > 3]
        
        print("🎯 Detected Attack Patterns:")
        print(f"   Port Scanning: {len(patterns['port_scanning'])} IPs")
        print(f"   Brute Force: {len(patterns['brute_force'])} IPs")
        
        return patterns
    
    def generate_report(self, output_file='attack_report.xlsx'):
        """Generate comprehensive attack report"""
        if not self.attacks:
            print("❌ No attack data to analyze")
            return
        
        # Create DataFrame for analysis
        df = pd.DataFrame(self.attacks)
        
        # Create Excel writer
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            # Summary sheet
            summary_data = {
                'Metric': ['Total Attacks', 'Unique Attackers', 'Time Period', 'Most Common Attack Type'],
                'Value': [
                    len(self.attacks),
                    df['ip'].nunique(),
                    f"{df['timestamp'].min()} to {df['timestamp'].max()}",
                    df['type'].mode().iloc[0] if not df.empty else 'None'
                ]
            }
            pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)
            
            # Attack details sheet
            df.to_excel(writer, sheet_name='Attack Details', index=False)
            
            # Patterns sheet
            patterns = self.detect_attack_patterns()
            pattern_data = {
                'Port Scanning IPs': patterns['port_scanning'],
                'Brute Force IPs': patterns['brute_force']
            }
            # Fill with empty strings to make equal length
            max_len = max(len(lst) for lst in pattern_data.values())
            for key in pattern_data:
                pattern_data[key] += [''] * (max_len - len(pattern_data[key]))
            
            pd.DataFrame(pattern_data).to_excel(writer, sheet_name='Attack Patterns', index=False)
        
        print(f"📄 Report generated: {output_file}")
    
    def create_visualizations(self):
        """Create attack visualization charts"""
        if not self.attacks:
            return
        
        df = pd.DataFrame(self.attacks)
        
        # Set up the plotting style
        plt.figure(figsize=(15, 10))
        
        # Plot 1: Attacks over time
        plt.subplot(2, 2, 1)
        df['time'] = df['timestamp'].dt.floor('H')
        time_counts = df.groupby('time').size()
        plt.plot(time_counts.index, time_counts.values, marker='o', linewidth=2)
        plt.title('Attack Frequency Over Time')
        plt.xlabel('Time')
        plt.ylabel('Number of Attacks')
        plt.xticks(rotation=45)
        
        # Plot 2: Attack types
        plt.subplot(2, 2, 2)
        attack_types = df['type'].value_counts()
        plt.pie(attack_types.values, labels=attack_types.index, autopct='%1.1f%%')
        plt.title('Attack Type Distribution')
        
        # Plot 3: Top attackers
        plt.subplot(2, 2, 3)
        top_attackers = df['ip'].value_counts().head(10)
        plt.bar(range(len(top_attackers)), top_attackers.values)
        plt.title('Top 10 Attackers by IP')
        plt.xlabel('IP Address')
        plt.ylabel('Number of Attacks')
        plt.xticks(range(len(top_attackers)), top_attackers.index, rotation=45)
        
        plt.tight_layout()
        plt.savefig('attack_analysis.png', dpi=300, bbox_inches='tight')
        print("📊 Visualizations saved: attack_analysis.png")

def main():
    analyzer = AttackChainAnalyzer()
    
    # Check if honeypot log exists
    log_file = 'honeypot.log'
    if not os.path.exists(log_file):
        print("❌ No honeypot log found.")
        return
    
    # Analyze the attacks
    analyzer.parse_honeypot_log(log_file)
    analyzer.generate_timeline()
    analyzer.detect_attack_patterns()
    analyzer.generate_report()
    analyzer.create_visualizations()
    
    print("\n🎉 Analysis Complete!")
    print("📁 Generated files:")
    print("   - attack_report.xlsx (detailed analysis)")
    print("   - attack_analysis.png (visualizations)")

if __name__ == "__main__":
    main()