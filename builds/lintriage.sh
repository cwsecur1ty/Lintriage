#!/bin/bash

# Lintriage - Linux Privilege Escalation Auto-Triage Tool
# Runs focused checks for common Linux privilege escalation vectors.

# Color codes
RED='\033[91m'
YELLOW='\033[93m'
BLUE='\033[94m'
GREEN='\033[92m'
CYAN='\033[96m'
MAGENTA='\033[95m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# Unicode symbols
CHECK='✓'
CROSS='✗'
WARN='⚠'
INFO='ℹ'
ARROW='➜'
DOT='•'

# Arrays to store results
declare -a HIGH_RESULTS
declare -a MEDIUM_RESULTS
declare -a INFO_RESULTS

# Function to add result
add_result() {
    local severity=$1
    local category=$2
    local message=$3
    local details=$4
    
    case $severity in
        HIGH)
            HIGH_RESULTS+=("$category|$message|$details")
            ;;
        MEDIUM)
            MEDIUM_RESULTS+=("$category|$message|$details")
            ;;
        INFO)
            INFO_RESULTS+=("$category|$message|$details")
            ;;
    esac
}

# Print header
print_header() {
    echo -e "${BOLD}${CYAN}"

    echo "     ${BOLD}${MAGENTA} ██      ██ ███    ██ ████████ ██████  ██  █████   ██████  ███████ ${CYAN}     "
    echo "     ${BOLD}${MAGENTA} ██      ██ ████   ██    ██    ██   ██ ██ ██   ██ ██       ██      ${CYAN}     "
    echo "     ${BOLD}${MAGENTA} ██      ██ ██ ██  ██    ██    ██████  ██ ███████ ██   ███ █████  ${CYAN}      "
    echo "     ${BOLD}${MAGENTA} ██      ██ ██  ██ ██    ██    ██   ██ ██ ██   ██ ██    ██ ██      ${CYAN}     "
    echo "     ${BOLD}${MAGENTA} ███████ ██ ██   ████    ██    ██   ██ ██ ██   ██  ██████  ███████ ${CYAN}     "
    echo "     ${BOLD}${YELLOW}Linux Privilege Escalation Auto-Triage Tool${CYAN}              "
    echo "    ${DIM}Focused enumeration without the noise${CYAN}                          "
    echo -e "${RESET}\n"
}

# Progress indicator
show_progress() {
    local check_name=$1
    echo -ne "\r${CYAN}${ARROW}${RESET} ${BOLD}${check_name}${RESET} ${DIM}[scanning...]${RESET}"
}

# Check SUID binaries
check_suid_binaries() {
    show_progress "Checking SUID binaries"
    
    # Known dangerous SUID binaries
    dangerous_suid="nmap vim nano find bash less more cp mv python python3 perl ruby awk sed tar zip unzip gzip gunzip"
    
    # Find SUID binaries using the classic method
    suid_binaries=$(timeout 30 find / -perm -4000 -type f 2>/dev/null)
    
    if [ $? -eq 124 ]; then
        add_result "INFO" "SUID Binary" "SUID check timed out" "System may be slow or find command restricted"
        echo -ne "\r${GREEN}${CHECK}${RESET} ${BOLD}SUID binaries${RESET} ${DIM}[timeout]${RESET}\n"
        return
    fi
    
    if [ -z "$suid_binaries" ]; then
        add_result "INFO" "SUID Binary" "No SUID binaries found or access denied" ""
        echo -ne "\r${GREEN}${CHECK}${RESET} ${BOLD}SUID binaries${RESET} ${DIM}[none found]${RESET}\n"
        return
    fi
    
    while IFS= read -r binary; do
        if [ -f "$binary" ] && [ -r "$binary" ]; then
            bin_name=$(basename "$binary")
            is_dangerous=false
            
            # Get binary details
            bin_owner=$(stat -c "%U" "$binary" 2>/dev/null || ls -ld "$binary" 2>/dev/null | awk '{print $3}')
            bin_perms=$(stat -c "%a" "$binary" 2>/dev/null || ls -ld "$binary" 2>/dev/null | awk '{print $1}')
            bin_size=$(stat -c "%s" "$binary" 2>/dev/null || ls -lh "$binary" 2>/dev/null | awk '{print $5}')
            
            # Build details string
            details="Binary: $bin_name"
            if [ -n "$bin_owner" ]; then
                details="$details | Owner: $bin_owner"
            fi
            if [ -n "$bin_perms" ]; then
                details="$details | Perms: $bin_perms"
            fi
            if [ -n "$bin_size" ]; then
                details="$details | Size: $bin_size"
            fi
            
            # Check if it's in the dangerous list
            for dangerous in $dangerous_suid; do
                if [ "$bin_name" = "$dangerous" ]; then
                    details="$details | Known to be exploitable"
                    add_result "HIGH" "SUID Binary" "Dangerous SUID binary: $binary" "$details"
                    is_dangerous=true
                    break
                fi
            done
            
            if [ "$is_dangerous" = false ]; then
                # Check if it's writable (even more dangerous)
                if [ -w "$binary" ] 2>/dev/null; then
                    details="$details | Writable!"
                    add_result "HIGH" "SUID Binary" "Writable SUID binary: $binary" "$details"
                else
                    add_result "MEDIUM" "SUID Binary" "SUID binary: $binary" "$details"
                fi
            fi
        fi
    done <<< "$suid_binaries"
    
    echo -ne "\r${GREEN}${CHECK}${RESET} ${BOLD}SUID binaries${RESET} ${GREEN}[completed]${RESET}\n"
}

# Check cron jobs
check_writable_cron() {
    show_progress "Checking cron jobs"
    
    cron_paths=(
        "/etc/crontab"
        "/etc/cron.d"
        "/etc/cron.daily"
        "/etc/cron.hourly"
        "/etc/cron.weekly"
        "/etc/cron.monthly"
        "/var/spool/cron"
        "/var/spool/cron/crontabs"
    )
    
    for cron_path in "${cron_paths[@]}"; do
        if [ -e "$cron_path" ]; then
            if [ -d "$cron_path" ]; then
                # Check if directory is writable
                if [ -w "$cron_path" ]; then
                    add_result "HIGH" "Writable Cron Directory" "Writable cron directory: $cron_path" "You can create cron jobs here for privilege escalation"
                fi
                
                # Check files in directory
                if [ -r "$cron_path" ]; then
                    while IFS= read -r file_path; do
                        if [ -f "$file_path" ]; then
                            # Check if writable
                            if [ -w "$file_path" ] 2>/dev/null; then
                                # Read cron content (show schedule and command)
                                cron_content=$(cat "$file_path" 2>/dev/null | grep -v "^#" | grep -v "^$" | head -5 | sed 's/^/  /')
                                if [ -n "$cron_content" ]; then
                                    add_result "HIGH" "Writable Cron File" "Writable cron file: $file_path" "You can modify this cron job. Current jobs:\n$cron_content"
                                else
                                    add_result "HIGH" "Writable Cron File" "Writable cron file: $file_path" "You can create cron jobs here for privilege escalation"
                                fi
                            else
                                # Readable but not writable - show info
                                if [ -r "$file_path" ]; then
                                    cron_content=$(cat "$file_path" 2>/dev/null | grep -v "^#" | grep -v "^$" | head -5 | sed 's/^/  /')
                                    if [ -n "$cron_content" ]; then
                                        # Check if any jobs run as root
                                        if grep -qE "^[^#]*root|^[^#]*[[:space:]]+root[[:space:]]" "$file_path" 2>/dev/null; then
                                            add_result "MEDIUM" "Cron File (Root)" "Cron file with root jobs: $file_path" "Contains root cron jobs:\n$cron_content"
                                        else
                                            add_result "INFO" "Cron File" "Cron file found: $file_path" "Jobs:\n$cron_content"
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    done < <(find "$cron_path" -type f 2>/dev/null)
                fi
            else
                # Check if file is writable
                if [ -w "$cron_path" ]; then
                    cron_content=$(cat "$cron_path" 2>/dev/null | grep -v "^#" | grep -v "^$" | head -10 | sed 's/^/  /')
                    if [ -n "$cron_content" ]; then
                        add_result "HIGH" "Writable Cron File" "Writable cron file: $cron_path" "You can modify this cron job. Current jobs:\n$cron_content"
                    else
                        add_result "HIGH" "Writable Cron File" "Writable cron file: $cron_path" "You can create cron jobs here for privilege escalation"
                    fi
                elif [ -r "$cron_path" ]; then
                    # Readable system crontab
                    cron_content=$(cat "$cron_path" 2>/dev/null | grep -v "^#" | grep -v "^$" | head -10 | sed 's/^/  /')
                    if [ -n "$cron_content" ]; then
                        # Check for root jobs
                        if grep -qE "^[[:space:]]*[^#]*root|^[[:space:]]*[^#]*[[:space:]]+root[[:space:]]" "$cron_path" 2>/dev/null; then
                            add_result "MEDIUM" "System Crontab (Root)" "System crontab with root jobs: $cron_path" "Contains root cron jobs:\n$cron_content"
                        else
                            add_result "INFO" "System Crontab" "System crontab: $cron_path" "Jobs:\n$cron_content"
                        fi
                    fi
                fi
            fi
        fi
    done
    
    # Check user crontabs
    if command -v crontab >/dev/null 2>&1; then
        # Current user
        user_crontab=$(timeout 5 crontab -l 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$user_crontab" ]; then
            # Filter out comments and empty lines
            active_jobs=$(echo "$user_crontab" | grep -v "^#" | grep -v "^$" | sed 's/^/  /')
            if [ -n "$active_jobs" ]; then
                job_count=$(echo "$active_jobs" | wc -l)
                add_result "INFO" "User Crontab" "Current user has $job_count cron job(s)" "Jobs:\n$active_jobs"
            fi
        fi
        
        # Check other users' crontabs if accessible
        if [ -d "/var/spool/cron/crontabs" ] && [ -r "/var/spool/cron/crontabs" ]; then
            for user_cron in /var/spool/cron/crontabs/*; do
                if [ -f "$user_cron" ] && [ -r "$user_cron" ]; then
                    username=$(basename "$user_cron")
                    if [ "$username" != "$(whoami)" ]; then
                        cron_content=$(cat "$user_cron" 2>/dev/null | grep -v "^#" | grep -v "^$" | head -5 | sed 's/^/  /')
                        if [ -n "$cron_content" ]; then
                            if [ -w "$user_cron" ] 2>/dev/null; then
                                add_result "HIGH" "Writable User Crontab" "Writable crontab for user: $username" "You can modify this. Jobs:\n$cron_content"
                            else
                                add_result "INFO" "User Crontab" "Crontab for user: $username" "Jobs:\n$cron_content"
                            fi
                        fi
                    fi
                fi
            done
        fi
    fi
    
    echo -ne "\r${GREEN}${CHECK}${RESET} ${BOLD}Cron jobs${RESET} ${GREEN}[completed]${RESET}\n"
}

# Check writable systemd services
check_writable_systemd() {
    show_progress "Checking writable systemd services"
    
    systemd_paths=(
        "/etc/systemd/system"
        "/usr/lib/systemd/system"
        "/lib/systemd/system"
        "/run/systemd/system"
    )
    
    for systemd_path in "${systemd_paths[@]}"; do
        if [ -d "$systemd_path" ]; then
            if [ -w "$systemd_path" ]; then
                add_result "HIGH" "Writable Systemd" "Writable systemd directory: $systemd_path" "You can create/modify systemd services here for privilege escalation"
            else
                # Check individual service files
                if [ -r "$systemd_path" ]; then
                    find "$systemd_path" -name "*.service" -type f 2>/dev/null | while read -r service_file; do
                        if [ -w "$service_file" ] 2>/dev/null; then
                            add_result "HIGH" "Writable Systemd" "Writable systemd service: $service_file" "You can modify this service for privilege escalation"
                        fi
                    done
                fi
            fi
        fi
    done
    
    echo -ne "\r${GREEN}${CHECK}${RESET} ${BOLD}Writable systemd services${RESET} ${GREEN}[completed]${RESET}\n"
}

# Check Linux capabilities
check_capabilities() {
    show_progress "Checking Linux capabilities"
    
    if ! command -v getcap >/dev/null 2>&1; then
        add_result "INFO" "Capabilities" "getcap command not found" "Cannot check capabilities"
        return
    fi
    
    # Dangerous capabilities (using case statement for compatibility)
    is_dangerous_cap() {
        case "$1" in
            cap_dac_read_search|cap_dac_override|cap_setuid|cap_setgid|cap_sys_admin|cap_sys_module|cap_sys_ptrace|cap_sys_rawio)
                return 0
                ;;
            *)
                return 1
                ;;
        esac
    }
    
    get_cap_description() {
        case "$1" in
            cap_dac_read_search) echo "Can read any file" ;;
            cap_dac_override) echo "Bypass file read, write, and execute permission checks" ;;
            cap_setuid) echo "Can set UID" ;;
            cap_setgid) echo "Can set GID" ;;
            cap_sys_admin) echo "Can perform system administration tasks" ;;
            cap_sys_module) echo "Can insert/remove kernel modules" ;;
            cap_sys_ptrace) echo "Can ptrace any process" ;;
            cap_sys_rawio) echo "Can perform raw I/O operations" ;;
            *) echo "" ;;
        esac
    }
    
    # Find files with capabilities
    cap_output=$(timeout 30 getcap -r / 2>/dev/null)
    
    if [ $? -eq 124 ]; then
        add_result "INFO" "Capabilities" "Capability check timed out" ""
        return
    fi
    
    if [ -z "$cap_output" ]; then
        add_result "INFO" "Capabilities" "No files with capabilities found" ""
        return
    fi
    
    while IFS= read -r line; do
        if [[ "$line" == *"="* ]]; then
            file_path=$(echo "$line" | cut -d'=' -f1 | xargs)
            caps=$(echo "$line" | cut -d'=' -f2 | xargs)
            
            has_dangerous=false
            dangerous_cap_list=""
            
            IFS=',' read -ra cap_array <<< "$caps"
            for cap in "${cap_array[@]}"; do
                cap=$(echo "$cap" | xargs)
                if is_dangerous_cap "$cap"; then
                    has_dangerous=true
                    cap_desc=$(get_cap_description "$cap")
                    if [ -z "$dangerous_cap_list" ]; then
                        dangerous_cap_list="$cap - $cap_desc"
                    else
                        dangerous_cap_list="$dangerous_cap_list, $cap - $cap_desc"
                    fi
                fi
            done
            
            if [ "$has_dangerous" = true ]; then
                add_result "HIGH" "Capabilities" "File with dangerous capability: $file_path" "Capability: $dangerous_cap_list"
            else
                add_result "MEDIUM" "Capabilities" "File with capability: $file_path" "Capabilities: $caps"
            fi
        fi
    done <<< "$cap_output"
    
    echo -ne "\r${GREEN}${CHECK}${RESET} ${BOLD}Linux capabilities${RESET} ${GREEN}[completed]${RESET}\n"
}

# Check interesting files
check_interesting_files() {
    show_progress "Scanning for interesting files"
    
    interesting_extensions=(".bak" ".old" ".conf" ".swp" ".tmp" ".log")
    interesting_paths=("/etc" "/home" "/root" "/tmp" "/var" "/opt")
    
    max_results=50
    found_count=0
    
    for path in "${interesting_paths[@]}"; do
        if [ -d "$path" ] && [ "$found_count" -lt "$max_results" ]; then
            for ext in "${interesting_extensions[@]}"; do
                if [ "$found_count" -ge "$max_results" ]; then
                    break
                fi
                
                # Use find with head to limit results
                find "$path" -maxdepth 3 -type f -name "*$ext" 2>/dev/null | head -n $((max_results - found_count)) | while read -r file_path; do
                    if [ "$found_count" -ge "$max_results" ]; then
                        break
                    fi
                    
                    if [ -r "$file_path" ]; then
                        found_count=$((found_count + 1))
                        
                        if [ -w "$file_path" ]; then
                            add_result "MEDIUM" "Interesting Files" "Writable interesting file: $file_path" "May contain sensitive information or be modifiable"
                        else
                            add_result "INFO" "Interesting Files" "Interesting file found: $file_path" "May contain sensitive information"
                        fi
                    fi
                done
            done
        fi
    done
    
    # Count total found for summary
    total_found=$(find "${interesting_paths[@]}" -maxdepth 3 -type f \( -name "*.bak" -o -name "*.old" -o -name "*.conf" -o -name "*.swp" -o -name "*.tmp" -o -name "*.log" \) 2>/dev/null | wc -l)
    
    if [ "$total_found" -gt "$max_results" ]; then
        add_result "INFO" "Interesting Files" "Found $total_found+ interesting files" "Too many results to display individually"
    fi
    
    echo -ne "\r${GREEN}${CHECK}${RESET} ${BOLD}Interesting files${RESET} ${GREEN}[completed]${RESET}\n"
}

# Check kernel version
check_kernel_exploits() {
    show_progress "Checking kernel version"
    
    if ! command -v uname >/dev/null 2>&1; then
        add_result "INFO" "Kernel Version" "uname command not found" ""
        return
    fi
    
    kernel_version=$(uname -r 2>/dev/null)
    
    if [ -z "$kernel_version" ]; then
        add_result "INFO" "Kernel Version" "Could not determine kernel version" ""
        return
    fi
    
    # Parse kernel version
    major=$(echo "$kernel_version" | cut -d'.' -f1)
    minor=$(echo "$kernel_version" | cut -d'.' -f2 | cut -d'-' -f1)
    
    # Convert to integers for comparison
    major_int=$((10#$major))
    minor_int=$((10#$minor))
    
    # Check if kernel is old (generally < 5.10 has more exploits)
    if [ "$major_int" -lt 5 ] || ([ "$major_int" -eq 5 ] && [ "$minor_int" -lt 10 ]); then
        add_result "MEDIUM" "Kernel Version" "Potentially vulnerable kernel: $kernel_version" "Kernel version $kernel_version may have known exploits. Check exploit-db.com for specific exploits."
    else
        add_result "INFO" "Kernel Version" "Kernel version: $kernel_version" "Newer kernel version, but still check exploit-db.com for specific exploits"
    fi
    
    # Get distribution info
    if [ -f "/etc/os-release" ]; then
        distro=$(grep "^PRETTY_NAME=" /etc/os-release 2>/dev/null | cut -d'=' -f2 | tr -d '"')
        if [ -n "$distro" ]; then
            add_result "INFO" "System Info" "Distribution: $distro" "Kernel: $kernel_version"
        fi
    fi
    
    echo -ne "\r${GREEN}${CHECK}${RESET} ${BOLD}Kernel version${RESET} ${GREEN}[completed]${RESET}\n"
}

# Check for root-owned writable files
check_root_writable_files() {
    show_progress "Checking root-owned writable files"
    
    # Find root-owned files, then check if writable
    # First get root-owned files, then filter by writability
    root_files=$(timeout 30 find / -user root -type f 2>/dev/null | head -100)
    
    if [ $? -eq 124 ]; then
        add_result "INFO" "Root Writable Files" "Root writable files check timed out" "System may be slow or find command restricted"
        echo -ne "\r${GREEN}${CHECK}${RESET} ${BOLD}Root writable files${RESET} ${DIM}[timeout]${RESET}\n"
        return
    fi
    
    if [ $? -eq 124 ]; then
        add_result "INFO" "Root Writable Files" "Root writable files check timed out" "System may be slow or find command restricted"
        echo -ne "\r${GREEN}${CHECK}${RESET} ${BOLD}Root writable files${RESET} ${DIM}[timeout]${RESET}\n"
        return
    fi
    
    if [ -z "$root_files" ]; then
        echo -ne "\r${GREEN}${CHECK}${RESET} ${BOLD}Root writable files${RESET} ${DIM}[none found]${RESET}\n"
        return
    fi
    
    # Filter out common false positives
    exclude_paths="/proc /sys /dev /run /tmp"
    
    count=0
    while IFS= read -r file_path; do
        # Skip excluded paths
        skip=false
        for exclude in $exclude_paths; do
            if [[ "$file_path" == "$exclude"* ]]; then
                skip=true
                break
            fi
        done
        
        if [ "$skip" = true ]; then
            continue
        fi
        
        # Check if file is writable by current user
        if [ -f "$file_path" ] && [ -w "$file_path" ] 2>/dev/null; then
            count=$((count + 1))
            
            # Get file details
            file_perms=$(stat -c "%a" "$file_path" 2>/dev/null || ls -ld "$file_path" 2>/dev/null | awk '{print $1}')
            file_size=$(stat -c "%s" "$file_path" 2>/dev/null || ls -lh "$file_path" 2>/dev/null | awk '{print $5}')
            
            # Check if it's in a sensitive location
            sensitive_locations="/etc /usr/bin /usr/sbin /bin /sbin /opt /var"
            is_sensitive=false
            for loc in $sensitive_locations; do
                if [[ "$file_path" == "$loc"* ]]; then
                    is_sensitive=true
                    break
                fi
            done
            
            # Build details
            details="File: $file_path"
            if [ -n "$file_perms" ]; then
                details="$details | Perms: $file_perms"
            fi
            if [ -n "$file_size" ]; then
                details="$details | Size: $file_size"
            fi
            
            # Check if it's executable (even more dangerous)
            if [ -x "$file_path" ] 2>/dev/null; then
                details="$details | Executable!"
                if [ "$is_sensitive" = true ]; then
                    add_result "HIGH" "Root Writable File" "Writable root executable in sensitive location: $file_path" "$details"
                else
                    add_result "HIGH" "Root Writable File" "Writable root executable: $file_path" "$details"
                fi
            elif [ "$is_sensitive" = true ]; then
                add_result "HIGH" "Root Writable File" "Writable root file in sensitive location: $file_path" "$details"
            else
                add_result "MEDIUM" "Root Writable File" "Writable root file: $file_path" "$details"
            fi
            
            # Limit results to avoid spam
            if [ $count -ge 20 ]; then
                add_result "INFO" "Root Writable Files" "Found 20+ root-owned writable files" "Too many to display individually. Use: find / -user root -type f -writable 2>/dev/null"
                break
            fi
        fi
    done <<< "$root_files"
    
    if [ $count -gt 0 ]; then
        echo -ne "\r${GREEN}${CHECK}${RESET} ${BOLD}Root writable files${RESET} ${GREEN}[found $count]${RESET}\n"
    else
        echo -ne "\r${GREEN}${CHECK}${RESET} ${BOLD}Root writable files${RESET} ${DIM}[none found]${RESET}\n"
    fi
}

# Print results
print_results() {
    echo -e "\n"
    echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${CYAN}║                    ${BOLD}SCAN RESULTS${CYAN}                      ║${RESET}"
    echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════════════╝${RESET}\n"
    
    # Print HIGH severity findings
    if [ ${#HIGH_RESULTS[@]} -gt 0 ]; then
        echo -e "${BOLD}${RED}┌────────────────────────────────────────────────────────────┐${RESET}"
        echo -e "${BOLD}${RED}│  ${WARN}  HIGH SEVERITY FINDINGS  ${RED}                                    │${RESET}"
        echo -e "${BOLD}${RED}└────────────────────────────────────────────────────────────┘${RESET}\n"
        
        count=1
        for result in "${HIGH_RESULTS[@]}"; do
            IFS='|' read -r category message details <<< "$result"
            echo -e "${RED}${DOT}${RESET} ${BOLD}${RED}[$count]${RESET} ${BOLD}$category${RESET}"
            echo -e "   ${ARROW} ${message}"
            if [ -n "$details" ]; then
                echo -e "   ${DIM}${YELLOW}└─${RESET} ${DIM}${YELLOW}$details${RESET}"
            fi
            echo
            count=$((count + 1))
        done
    fi
    
    # Print MEDIUM severity findings
    if [ ${#MEDIUM_RESULTS[@]} -gt 0 ]; then
        echo -e "${BOLD}${YELLOW}┌────────────────────────────────────────────────────────────┐${RESET}"
        echo -e "${BOLD}${YELLOW}│  ${WARN}  MEDIUM SEVERITY FINDINGS  ${YELLOW}                                 │${RESET}"
        echo -e "${BOLD}${YELLOW}└────────────────────────────────────────────────────────────┘${RESET}\n"
        
        count=1
        for result in "${MEDIUM_RESULTS[@]}"; do
            IFS='|' read -r category message details <<< "$result"
            echo -e "${YELLOW}${DOT}${RESET} ${BOLD}${YELLOW}[$count]${RESET} ${BOLD}$category${RESET}"
            echo -e "   ${ARROW} ${message}"
            if [ -n "$details" ]; then
                echo -e "   ${DIM}└─${RESET} ${DIM}$details${RESET}"
            fi
            echo
            count=$((count + 1))
        done
    fi
    
    # Print INFO findings
    if [ ${#INFO_RESULTS[@]} -gt 0 ]; then
        echo -e "${BOLD}${BLUE}┌────────────────────────────────────────────────────────────┐${RESET}"
        echo -e "${BOLD}${BLUE}│  ${INFO}  INFO FINDINGS  ${BLUE}                                          │${RESET}"
        echo -e "${BOLD}${BLUE}└────────────────────────────────────────────────────────────┘${RESET}\n"
        
        count=1
        for result in "${INFO_RESULTS[@]}"; do
            IFS='|' read -r category message details <<< "$result"
            echo -e "${BLUE}${DOT}${RESET} ${BOLD}${BLUE}[$count]${RESET} ${BOLD}$category${RESET}"
            echo -e "   ${ARROW} ${message}"
            if [ -n "$details" ]; then
                echo -e "   ${DIM}└─${RESET} ${DIM}$details${RESET}"
            fi
            echo
            count=$((count + 1))
        done
    fi
    
    # Summary box
    echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${CYAN}║                        ${BOLD}SUMMARY${CYAN}                         ║${RESET}"
    echo -e "${BOLD}${CYAN}╠════════════════════════════════════════════════════════════╣${RESET}"
    
    # Calculate totals
    high_count=${#HIGH_RESULTS[@]}
    medium_count=${#MEDIUM_RESULTS[@]}
    info_count=${#INFO_RESULTS[@]}
    total=$((high_count + medium_count + info_count))
    
    # Format summary with padding
    printf "${BOLD}${CYAN}║${RESET}  ${RED}${BOLD}HIGH:${RESET}   %-3s ${CYAN}│${RESET}  ${YELLOW}${BOLD}MEDIUM:${RESET} %-3s ${CYAN}│${RESET}  ${BLUE}${BOLD}INFO:${RESET}   %-3s ${CYAN}│${RESET}  ${BOLD}TOTAL:${RESET} %-3s ${CYAN}║${RESET}\n" \
           "$high_count" "$medium_count" "$info_count" "$total"
    
    echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════════════╝${RESET}\n"
    
    # Final message
    if [ $high_count -gt 0 ]; then
        echo -e "${BOLD}${RED}${WARN} ${high_count} high severity finding(s) require immediate attention!${RESET}\n"
    elif [ $medium_count -gt 0 ]; then
        echo -e "${BOLD}${YELLOW}${INFO} ${medium_count} medium severity finding(s) should be reviewed.${RESET}\n"
    else
        echo -e "${BOLD}${GREEN}${CHECK} Scan completed. No critical findings detected.${RESET}\n"
    fi
}

# Main function
main() {
    print_header
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}${WARN}${RESET} ${BOLD}Warning:${RESET} Not running as root. Some checks may be limited.\n"
        echo -e "${DIM}   Consider running with: ${BOLD}sudo ./lintriage.sh${RESET}\n"
    fi
    
    echo -e "${BOLD}${CYAN}Starting enumeration...${RESET}\n"
    echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
    
    # Run all checks
    check_suid_binaries
    check_writable_cron
    check_writable_systemd
    check_capabilities
    check_interesting_files
    check_kernel_exploits
    check_root_writable_files
    
    echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
    echo -e "${GREEN}${CHECK}${RESET} ${BOLD}All checks completed!${RESET}\n"
    
    # Print results
    print_results
}

# Run main function
main
