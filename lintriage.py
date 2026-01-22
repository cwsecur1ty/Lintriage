#!/usr/bin/env python3
"""
Lintriage - Linux Privilege Escalation Auto-Triage Tool
Runs focused checks for common Linux privilege escalation vectors.
"""

import os
import sys
import subprocess
import re
import json
import argparse
import http.server
import socketserver
import socket
import threading
from pathlib import Path
from typing import List, Dict, Tuple
from collections import defaultdict

# Color codes for output
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

class Lintriage:
    def __init__(self):
        self.results = {
            'HIGH': [],
            'MEDIUM': [],
            'INFO': []
        }
        
    def print_header(self):
        """Print tool header"""
        print(f"{Colors.BOLD}{Colors.BLUE}")
        print("=" * 60)
        print("  Lintriage - Linux PrivEsc Auto-Triage Tool")
        print("=" * 60)
        print(f"{Colors.RESET}\n")
    
    def add_result(self, severity: str, category: str, message: str, details: str = ""):
        """Add a finding to results"""
        if severity in self.results:
            self.results[severity].append({
                'category': category,
                'message': message,
                'details': details
            })
    
    def check_suid_binaries(self):
        """Check for SUID binaries"""
        print(f"{Colors.BLUE}[*] Checking SUID binaries...{Colors.RESET}")
        suid_binaries = []
        
        try:
            # Find all SUID binaries
            result = subprocess.run(
                ['find', '/', '-perm', '-4000', '-type', 'f', '2>/dev/null'],
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and os.path.exists(line):
                        suid_binaries.append(line)
            
            # Known dangerous SUID binaries
            dangerous_suid = [
                'nmap', 'vim', 'nano', 'find', 'bash', 'less', 'more',
                'nano', 'cp', 'mv', 'python', 'python3', 'perl', 'ruby',
                'awk', 'sed', 'tar', 'zip', 'unzip', 'gzip', 'gunzip'
            ]
            
            for binary in suid_binaries:
                bin_name = os.path.basename(binary)
                if bin_name in dangerous_suid:
                    self.add_result(
                        'HIGH',
                        'SUID Binary',
                        f"Dangerous SUID binary found: {binary}",
                        f"Binary: {bin_name} - Known to be exploitable"
                    )
                else:
                    self.add_result(
                        'MEDIUM',
                        'SUID Binary',
                        f"SUID binary found: {binary}",
                        f"Binary: {bin_name} - Review for exploitation potential"
                    )
                    
        except subprocess.TimeoutExpired:
            self.add_result('INFO', 'SUID Binary', 'SUID check timed out', 'System may be slow or find command restricted')
        except Exception as e:
            self.add_result('INFO', 'SUID Binary', f'Error checking SUID binaries: {str(e)}', '')
    
    def check_writable_cron(self):
        """Check for writable cron jobs"""
        print(f"{Colors.BLUE}[*] Checking writable cron jobs...{Colors.RESET}")
        
        cron_paths = [
            '/etc/crontab',
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.weekly',
            '/etc/cron.monthly',
            '/var/spool/cron',
            '/var/spool/cron/crontabs'
        ]
        
        for cron_path in cron_paths:
            if os.path.exists(cron_path):
                if os.path.isdir(cron_path):
                    # Check if directory is writable
                    if os.access(cron_path, os.W_OK):
                        self.add_result(
                            'HIGH',
                            'Writable Cron',
                            f"Writable cron directory: {cron_path}",
                            "You can create cron jobs here for privilege escalation"
                        )
                    # Check files in directory
                    try:
                        for root, dirs, files in os.walk(cron_path):
                            for file in files:
                                file_path = os.path.join(root, file)
                                if os.access(file_path, os.W_OK):
                                    self.add_result(
                                        'HIGH',
                                        'Writable Cron',
                                        f"Writable cron file: {file_path}",
                                        "You can modify this cron job for privilege escalation"
                                    )
                    except PermissionError:
                        pass
                else:
                    # Check if file is writable
                    if os.access(cron_path, os.W_OK):
                        self.add_result(
                            'HIGH',
                            'Writable Cron',
                            f"Writable cron file: {cron_path}",
                            "You can modify this cron job for privilege escalation"
                        )
        
        # Check user crontabs
        try:
            result = subprocess.run(
                ['crontab', '-l'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                self.add_result(
                    'INFO',
                    'Cron Jobs',
                    'User has cron jobs configured',
                    f"Cron jobs:\n{result.stdout.strip()}"
                )
        except:
            pass
    
    def check_writable_systemd(self):
        """Check for writable systemd services"""
        print(f"{Colors.BLUE}[*] Checking writable systemd services...{Colors.RESET}")
        
        systemd_paths = [
            '/etc/systemd/system',
            '/usr/lib/systemd/system',
            '/lib/systemd/system',
            '/run/systemd/system'
        ]
        
        for systemd_path in systemd_paths:
            if os.path.exists(systemd_path) and os.path.isdir(systemd_path):
                if os.access(systemd_path, os.W_OK):
                    self.add_result(
                        'HIGH',
                        'Writable Systemd',
                        f"Writable systemd directory: {systemd_path}",
                        "You can create/modify systemd services here for privilege escalation"
                    )
                else:
                    # Check individual service files
                    try:
                        for root, dirs, files in os.walk(systemd_path):
                            for file in files:
                                if file.endswith('.service'):
                                    file_path = os.path.join(root, file)
                                    if os.access(file_path, os.W_OK):
                                        self.add_result(
                                            'HIGH',
                                            'Writable Systemd',
                                            f"Writable systemd service: {file_path}",
                                            "You can modify this service for privilege escalation"
                                        )
                    except PermissionError:
                        pass
    
    def check_capabilities(self):
        """Check for interesting Linux capabilities"""
        print(f"{Colors.BLUE}[*] Checking Linux capabilities...{Colors.RESET}")
        
        dangerous_caps = {
            'cap_dac_read_search': 'Can read any file',
            'cap_dac_override': 'Bypass file read, write, and execute permission checks',
            'cap_setuid': 'Can set UID',
            'cap_setgid': 'Can set GID',
            'cap_sys_admin': 'Can perform system administration tasks',
            'cap_sys_module': 'Can insert/remove kernel modules',
            'cap_sys_ptrace': 'Can ptrace any process',
            'cap_sys_rawio': 'Can perform raw I/O operations'
        }
        
        try:
            # Check for getcap command
            result = subprocess.run(
                ['which', 'getcap'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                # Find files with capabilities
                cap_result = subprocess.run(
                    ['getcap', '-r', '/', '2>/dev/null'],
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if cap_result.returncode == 0:
                    for line in cap_result.stdout.strip().split('\n'):
                        if line and '=' in line:
                            parts = line.split('=')
                            if len(parts) == 2:
                                file_path = parts[0].strip()
                                caps = parts[1].strip()
                                
                                # Check for dangerous capabilities
                                for cap in caps.split(','):
                                    cap = cap.strip()
                                    if cap in dangerous_caps:
                                        self.add_result(
                                            'HIGH',
                                            'Capabilities',
                                            f"File with dangerous capability: {file_path}",
                                            f"Capability: {cap} - {dangerous_caps[cap]}"
                                        )
                                    else:
                                        self.add_result(
                                            'MEDIUM',
                                            'Capabilities',
                                            f"File with capability: {file_path}",
                                            f"Capabilities: {caps}"
                                        )
            else:
                self.add_result('INFO', 'Capabilities', 'getcap command not found', 'Cannot check capabilities')
                
        except subprocess.TimeoutExpired:
            self.add_result('INFO', 'Capabilities', 'Capability check timed out', '')
        except Exception as e:
            self.add_result('INFO', 'Capabilities', f'Error checking capabilities: {str(e)}', '')
    
    def check_interesting_files(self):
        """Check for interesting files (.bak, .old, .conf)"""
        print(f"{Colors.BLUE}[*] Checking for interesting files...{Colors.RESET}")
        
        interesting_extensions = ['.bak', '.old', '.conf', '.swp', '.tmp', '.log']
        interesting_paths = [
            '/etc',
            '/home',
            '/root',
            '/tmp',
            '/var',
            '/opt'
        ]
        
        found_files = []
        
        for path in interesting_paths:
            if os.path.exists(path):
                try:
                    for root, dirs, files in os.walk(path):
                        # Limit depth to avoid too many results
                        depth = root[len(path):].count(os.sep)
                        if depth > 3:
                            dirs[:] = []
                            continue
                            
                        for file in files:
                            file_path = os.path.join(root, file)
                            # Check if file has interesting extension
                            if any(file.endswith(ext) for ext in interesting_extensions):
                                # Check if readable
                                if os.access(file_path, os.R_OK):
                                    found_files.append(file_path)
                                    
                                    # Check if writable
                                    if os.access(file_path, os.W_OK):
                                        self.add_result(
                                            'MEDIUM',
                                            'Interesting Files',
                                            f"Writable interesting file: {file_path}",
                                            "May contain sensitive information or be modifiable"
                                        )
                                    else:
                                        self.add_result(
                                            'INFO',
                                            'Interesting Files',
                                            f"Interesting file found: {file_path}",
                                            "May contain sensitive information"
                                        )
                                        
                        # Limit results
                        if len(found_files) > 50:
                            break
                            
                except PermissionError:
                    pass
                except Exception as e:
                    pass
        
        if len(found_files) > 50:
            self.add_result(
                'INFO',
                'Interesting Files',
                f"Found {len(found_files)}+ interesting files",
                "Too many results to display individually"
            )
    
    def check_kernel_exploits(self):
        """Check kernel version against exploit-db"""
        print(f"{Colors.BLUE}[*] Checking kernel version...{Colors.RESET}")
        
        try:
            # Get kernel version
            result = subprocess.run(
                ['uname', '-r'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                kernel_version = result.stdout.strip()
                
                # Parse kernel version
                version_parts = kernel_version.split('.')
                if len(version_parts) >= 2:
                    major = int(version_parts[0])
                    minor = int(version_parts[1].split('-')[0])
                    
                    # Check for known vulnerable kernel versions
                    vulnerable_versions = [
                        (3, 0, "Multiple vulnerabilities"),
                        (3, 1, "Multiple vulnerabilities"),
                        (3, 2, "Multiple vulnerabilities"),
                        (3, 3, "Multiple vulnerabilities"),
                        (3, 4, "Multiple vulnerabilities"),
                        (3, 5, "Multiple vulnerabilities"),
                        (3, 6, "Multiple vulnerabilities"),
                        (3, 7, "Multiple vulnerabilities"),
                        (3, 8, "Multiple vulnerabilities"),
                        (3, 9, "Multiple vulnerabilities"),
                        (4, 0, "Multiple vulnerabilities"),
                        (4, 1, "Multiple vulnerabilities"),
                        (4, 2, "Multiple vulnerabilities"),
                        (4, 3, "Multiple vulnerabilities"),
                        (4, 4, "Multiple vulnerabilities"),
                        (4, 5, "Multiple vulnerabilities"),
                        (4, 6, "Multiple vulnerabilities"),
                        (4, 7, "Multiple vulnerabilities"),
                        (4, 8, "Multiple vulnerabilities"),
                        (4, 9, "Multiple vulnerabilities"),
                        (5, 0, "Multiple vulnerabilities"),
                        (5, 1, "Multiple vulnerabilities"),
                        (5, 2, "Multiple vulnerabilities"),
                        (5, 3, "Multiple vulnerabilities"),
                        (5, 4, "Multiple vulnerabilities"),
                        (5, 5, "Multiple vulnerabilities"),
                        (5, 6, "Multiple vulnerabilities"),
                        (5, 7, "Multiple vulnerabilities"),
                        (5, 8, "Multiple vulnerabilities"),
                        (5, 9, "Multiple vulnerabilities"),
                    ]
                    
                    # Check if kernel is old (generally < 5.10 has more exploits)
                    if major < 5 or (major == 5 and minor < 10):
                        self.add_result(
                            'MEDIUM',
                            'Kernel Version',
                            f"Potentially vulnerable kernel: {kernel_version}",
                            f"Kernel version {kernel_version} may have known exploits. Check exploit-db.com for specific exploits."
                        )
                    else:
                        self.add_result(
                            'INFO',
                            'Kernel Version',
                            f"Kernel version: {kernel_version}",
                            "Newer kernel version, but still check exploit-db.com for specific exploits"
                        )
                    
                    # Additional kernel info
                    try:
                        distro_result = subprocess.run(
                            ['cat', '/etc/os-release'],
                            capture_output=True,
                            text=True
                        )
                        if distro_result.returncode == 0:
                            for line in distro_result.stdout.split('\n'):
                                if line.startswith('PRETTY_NAME='):
                                    distro = line.split('=')[1].strip('"')
                                    self.add_result(
                                        'INFO',
                                        'System Info',
                                        f"Distribution: {distro}",
                                        f"Kernel: {kernel_version}"
                                    )
                                    break
                    except:
                        pass
                        
        except Exception as e:
            self.add_result('INFO', 'Kernel Version', f'Error checking kernel: {str(e)}', '')
    
    def print_results(self):
        """Print formatted results"""
        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.RESET}\n")
        
        # Print HIGH severity findings
        if self.results['HIGH']:
            print(f"{Colors.BOLD}{Colors.RED}HIGH SEVERITY FINDINGS{Colors.RESET}")
            print(f"{Colors.RED}{'=' * 60}{Colors.RESET}\n")
            for i, finding in enumerate(self.results['HIGH'], 1):
                print(f"{Colors.RED}[{i}] {finding['category']}{Colors.RESET}")
                print(f"    {finding['message']}")
                if finding['details']:
                    print(f"    {Colors.YELLOW}Details: {finding['details']}{Colors.RESET}")
                print()
        
        # Print MEDIUM severity findings
        if self.results['MEDIUM']:
            print(f"{Colors.BOLD}{Colors.YELLOW}MEDIUM SEVERITY FINDINGS{Colors.RESET}")
            print(f"{Colors.YELLOW}{'=' * 60}{Colors.RESET}\n")
            for i, finding in enumerate(self.results['MEDIUM'], 1):
                print(f"{Colors.YELLOW}[{i}] {finding['category']}{Colors.RESET}")
                print(f"    {finding['message']}")
                if finding['details']:
                    print(f"    Details: {finding['details']}")
                print()
        
        # Print INFO findings
        if self.results['INFO']:
            print(f"{Colors.BOLD}{Colors.BLUE}INFO FINDINGS{Colors.RESET}")
            print(f"{Colors.BLUE}{'=' * 60}{Colors.RESET}\n")
            for i, finding in enumerate(self.results['INFO'], 1):
                print(f"{Colors.BLUE}[{i}] {finding['category']}{Colors.RESET}")
                print(f"    {finding['message']}")
                if finding['details']:
                    print(f"    Details: {finding['details']}")
                print()
        
        # Summary
        print(f"{Colors.BOLD}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}Summary:{Colors.RESET}")
        print(f"  {Colors.RED}HIGH:   {len(self.results['HIGH'])}{Colors.RESET}")
        print(f"  {Colors.YELLOW}MEDIUM: {len(self.results['MEDIUM'])}{Colors.RESET}")
        print(f"  {Colors.BLUE}INFO:   {len(self.results['INFO'])}{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 60}{Colors.RESET}\n")
    
    def run(self):
        """Run all checks"""
        self.print_header()
        
        # Run all checks
        self.check_suid_binaries()
        self.check_writable_cron()
        self.check_writable_systemd()
        self.check_capabilities()
        self.check_interesting_files()
        self.check_kernel_exploits()
        
        # Print results
        self.print_results()

def get_local_ip():
    """Get the local IP address"""
    try:
        # Connect to a remote address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def serve_build(port=8000):
    """Serve the lintriage.sh file via HTTP"""
    build_dir = Path(__file__).parent / "builds"
    build_file = build_dir / "lintriage.sh"
    
    if not build_file.exists():
        print(f"{Colors.RED}[!] Error: {build_file} not found!{Colors.RESET}")
        sys.exit(1)
    
    # Change to builds directory
    os.chdir(build_dir)
    
    class BuildHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            # Custom logging
            print(f"{Colors.GREEN}[*]{Colors.RESET} {args[0]}")
    
    try:
        with socketserver.TCPServer(("", port), BuildHandler) as httpd:
            local_ip = get_local_ip()
            print(f"\n{Colors.BOLD}{Colors.GREEN}╔════════════════════════════════════════════════════════════╗{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.GREEN}║     Lintriage Build Server - Ready to Serve{Colors.RESET:>20} ║")
            print(f"{Colors.BOLD}{Colors.GREEN}╚════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
            print(f"{Colors.BOLD}Server started on:{Colors.RESET}")
            print(f"  {Colors.CYAN}Local:   {Colors.RESET}http://127.0.0.1:{port}/lintriage.sh")
            print(f"  {Colors.CYAN}Network: {Colors.RESET}http://{local_ip}:{port}/lintriage.sh\n")
            print(f"{Colors.YELLOW}Download commands for target machine:{Colors.RESET}\n")
            print(f"  {Colors.BOLD}wget:{Colors.RESET}")
            print(f"    {Colors.DIM}wget http://{local_ip}:{port}/lintriage.sh -O lintriage.sh{Colors.RESET}\n")
            print(f"  {Colors.BOLD}curl:{Colors.RESET}")
            print(f"    {Colors.DIM}curl http://{local_ip}:{port}/lintriage.sh -o lintriage.sh{Colors.RESET}\n")
            print(f"  {Colors.BOLD}After download:{Colors.RESET}")
            print(f"    {Colors.DIM}chmod +x lintriage.sh{Colors.RESET}")
            print(f"    {Colors.DIM}./lintriage.sh{Colors.RESET}\n")
            print(f"{Colors.BOLD}{Colors.YELLOW}Press Ctrl+C to stop the server{Colors.RESET}\n")
            print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}\n")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Server stopped.{Colors.RESET}\n")
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"{Colors.RED}[!] Error: Port {port} is already in use.{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Try a different port: python lintriage.py serve --port 8080{Colors.RESET}\n")
        else:
            print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}\n")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Lintriage - Linux Privilege Escalation Auto-Triage Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run locally (requires Linux)
  python lintriage.py

  # Serve the bash script for download
  python lintriage.py serve

  # Serve on a custom port
  python lintriage.py serve --port 8080
        """
    )
    
    parser.add_argument(
        'command',
        nargs='?',
        default='run',
        choices=['run', 'serve'],
        help='Command to execute: run (default) or serve'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=8000,
        help='Port to serve on (default: 8000)'
    )
    
    args = parser.parse_args()
    
    if args.command == 'serve':
        serve_build(args.port)
    else:
        # Check if running on Linux
        if sys.platform not in ['linux', 'linux2']:
            print(f"{Colors.YELLOW}[!] Warning: This tool is designed for Linux systems.{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Use 'python lintriage.py serve' to serve the bash script instead.{Colors.RESET}\n")
            sys.exit(1)
        
        if os.geteuid() != 0:
            print(f"{Colors.YELLOW}[!] Warning: Not running as root. Some checks may be limited.{Colors.RESET}\n")
        
        tool = Lintriage()
        tool.run()

if __name__ == '__main__':
    main()
