#!/usr/bin/env python3
"""
Enhanced logging system for malware scanner with improved formatting
"""

import os
import json
import csv
from datetime import datetime
from typing import Dict, Any

class EnhancedLogger:
    """Enhanced logging class with multiple output formats"""
    
    def __init__(self, base_path: str, date_str: str):
        self.base_path = base_path
        self.date_str = date_str
        self.output_dir = f'{base_path}/output'
        
        # Ensure output directory exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def log_threat_detection(self, scan_data: Dict[str, Any], format_type: str = 'structured'):
        """
        Log threat detection with improved formatting
        
        Args:
            scan_data: Dictionary containing scan information
            format_type: 'structured', 'json', 'csv', or 'table'
        """
        if format_type == 'structured':
            self._log_structured_format(scan_data)
        elif format_type == 'json':
            self._log_json_format(scan_data)
        elif format_type == 'csv':
            self._log_csv_format(scan_data)
        elif format_type == 'table':
            self._log_table_format(scan_data)
    
    def _log_structured_format(self, scan_data: Dict[str, Any]):
        """Log in a structured, human-readable format"""
        log_file = f'{self.output_dir}/{self.date_str}-threats-structured.log'
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"THREAT DETECTION REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Detection Time    : {scan_data['datetime']}\n")
            f.write(f"Scan ID          : {scan_data['scan_id']}\n")
            f.write(f"System Info      : {scan_data['os']} | {scan_data['hostname']} | {scan_data['ip']}\n")
            f.write(f"Infected File    : {scan_data['infected_file']}\n")
            f.write(f"SHA256 Hash      : {scan_data['sha256']}\n")
            f.write(f"File Created     : {scan_data['created_at']}\n")
            f.write(f"File Modified    : {scan_data['modified_at']}\n")
            f.write("=" * 80 + "\n\n")
    
    def _log_json_format(self, scan_data: Dict[str, Any]):
        """Log in JSON format for easy parsing"""
        log_file = f'{self.output_dir}/{self.date_str}-threats.json'
        
        # Read existing data if file exists
        threats = []
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    threats = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                threats = []
        
        # Add new threat
        threats.append(scan_data)
        
        # Write back to file
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(threats, f, indent=2, ensure_ascii=False)
    
    def _log_csv_format(self, scan_data: Dict[str, Any]):
        """Log in CSV format for spreadsheet analysis"""
        log_file = f'{self.output_dir}/{self.date_str}-threats.csv'
        
        # Check if file exists to determine if we need headers
        file_exists = os.path.exists(log_file)
        
        with open(log_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=scan_data.keys())
            
            # Write header if file is new
            if not file_exists:
                writer.writeheader()
            
            writer.writerow(scan_data)
    
    def _log_table_format(self, scan_data: Dict[str, Any]):
        """Log in a formatted table structure"""
        log_file = f'{self.output_dir}/{self.date_str}-threats-table.log'
        
        # Check if this is the first entry
        file_exists = os.path.exists(log_file)
        
        with open(log_file, 'a', encoding='utf-8') as f:
            if not file_exists:
                # Write table header
                f.write("┌" + "─" * 78 + "┐\n")
                f.write("│" + " " * 30 + "MALWARE DETECTION LOG" + " " * 27 + "│\n")
                f.write("├" + "─" * 78 + "┤\n")
                f.write("│ Time            │ File                     │ SHA256 Hash      │ Status │\n")
                f.write("├" + "─" * 78 + "┤\n")
            
            # Format the data for table display
            time_str = scan_data['datetime'][:16]  # Truncate to HH:MM
            file_name = os.path.basename(scan_data['infected_file'])[:23]  # Truncate filename
            hash_short = scan_data['sha256'][:16]  # First 16 chars of hash
            
            f.write(f"│ {time_str:<15} │ {file_name:<23} │ {hash_short:<16} │ THREAT │\n")
    
    def log_clean_scan(self, scan_data: Dict[str, Any]):
        """Log clean scan results"""
        log_file = f'{self.output_dir}/{self.date_str}-clean-scans.log'
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"[{scan_data['datetime']}] CLEAN SCAN - "
                   f"Scan ID: {scan_data['scan_id']} | "
                   f"System: {scan_data['hostname']} ({scan_data['ip']}) | "
                   f"OS: {scan_data['os']}\n")
    
    def create_scan_summary(self, scan_stats: Dict[str, Any]):
        """Create a comprehensive scan summary report"""
        summary_file = f'{self.output_dir}/{self.date_str}-scan-summary.txt'
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("╔" + "═" * 78 + "╗\n")
            f.write("║" + " " * 25 + "MALWARE SCAN SUMMARY REPORT" + " " * 25 + "║\n")
            f.write("╠" + "═" * 78 + "╣\n")
            f.write(f"║ Scan Date/Time    : {scan_stats.get('scan_time', 'N/A'):<53} ║\n")
            f.write(f"║ Scan ID           : {scan_stats.get('scan_id', 'N/A'):<53} ║\n")
            f.write(f"║ Scanned Directory : {scan_stats.get('scan_path', 'N/A'):<53} ║\n")
            f.write("╠" + "═" * 78 + "╣\n")
            f.write(f"║ Total Files       : {scan_stats.get('total_files', 0):<53} ║\n")
            f.write(f"║ Files Scanned     : {scan_stats.get('scanned_files', 0):<53} ║\n")
            f.write(f"║ Threats Detected  : {scan_stats.get('threats_found', 0):<53} ║\n")
            f.write(f"║ Scan Duration     : {scan_stats.get('duration', 'N/A'):<53} ║\n")
            f.write(f"║ Scan Speed        : {scan_stats.get('speed', 'N/A'):<53} ║\n")
            f.write("╠" + "═" * 78 + "╣\n")
            f.write(f"║ System Info       : {scan_stats.get('system_info', 'N/A'):<53} ║\n")
            f.write(f"║ Engine Version    : {scan_stats.get('engine_version', 'N/A'):<53} ║\n")
            f.write(f"║ Signatures        : {scan_stats.get('signatures', 'N/A'):<53} ║\n")
            f.write("╚" + "═" * 78 + "╝\n")


def demo_enhanced_logging():
    """Demonstrate the enhanced logging formats"""
    logger = EnhancedLogger(".", "2025-07-29")
    
    # Sample threat data
    threat_data = {
        "datetime": "2025-07-29 11:53:37",
        "scan_id": "a0dfc486-00c4-4071-a4ea-1a54b081c285",
        "os": "Windows",
        "hostname": "Windows-786",
        "ip": "192.168.109.208",
        "infected_file": "C:\\Users\\Admin\\Pictures\\Saved Pictures\\malware_sample.xapk",
        "sha256": "b8f21f17e79ca095fce11156b02bf6611abaf18b4bdf298ffffa42b8d7cbec57",
        "created_at": "2025-03-29 16:42:36",
        "modified_at": "2025-03-29 11:06:16"
    }
    
    # Log in different formats
    logger.log_threat_detection(threat_data, 'structured')
    logger.log_threat_detection(threat_data, 'json')
    logger.log_threat_detection(threat_data, 'csv')
    logger.log_threat_detection(threat_data, 'table')
    
    # Sample scan summary
    scan_summary = {
        "scan_time": "2025-07-29 11:53:37",
        "scan_id": "a0dfc486-00c4-4071-a4ea-1a54b081c285",
        "scan_path": "C:\\Users\\Admin\\Pictures\\Saved Pictures",
        "total_files": 50,
        "scanned_files": 50,
        "threats_found": 1,
        "duration": "2.5 seconds",
        "speed": "20.0 files/sec",
        "system_info": "Windows-786 (192.168.109.208)",
        "engine_version": "2025-07-29",
        "signatures": "956,413"
    }
    
    logger.create_scan_summary(scan_summary)
    
    print("Enhanced logging demo completed! Check the output directory for various log formats.")


if __name__ == '__main__':
    demo_enhanced_logging()
