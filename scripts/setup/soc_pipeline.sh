#!/usr/bin/env bash
# =============================================================================
# Suburban-SOC Pipeline Automation Script
# SOP Reference: docs/SOP-001-pipeline-operations.md
# Owner: Tommy Lammers (@voltron-1) - Security Analyst / Manager
# Version: 1.7 | CIS 3353 Spring 2026
# =============================================================================

# --- Colors ---
# Define ANSI color codes for formatted and readable terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color (resets terminal formatting)

# --- Global Variables ---
# Determine the absolute path of the directory containing this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Set the default directory where Zeek logs will be stored
LOG_DIR="/storage/PCAP/zeek_logs"
# Default username for SSH connections to the router
ROUTER_USER="${ROUTER_USER:-root}"
# ROUTER_IP is dynamically configured later in the script
# ES_USER and ES_PASS are dynamically configured later in the script

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Prints the main banner for the tool
print_header() {
    echo -e "\n${CYAN}${BOLD}============================================${NC}"
    echo -e "${CYAN}${BOLD}  Suburban-SOC Pipeline Automation${NC}"
    echo -e "${CYAN}${BOLD}  CIS 3353 | Spring 2026${NC}"
    echo -e "${CYAN}${BOLD}============================================${NC}\n"
}

# Prints a formatted section header for sub-menus and steps
print_section() {
    echo -e "\n${BOLD}>>> $1${NC}"
    echo -e "${CYAN}--------------------------------------------${NC}"
}

# Standardized logging functions for consistent output formatting
pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }

# Prompts the user for a yes/no confirmation. Returns true (0) if Y/y, false otherwise.
confirm() {
    echo -ne "${YELLOW}  Proceed? [y/N]: ${NC}"
    read -r choice
    [[ "$choice" =~ ^[Yy]$ ]]
}

# =============================================================================
# CONFIGURATION MODULES
# =============================================================================

# Dynamically identifies or prompts for the network's router IP
configure_router_ip() {
    print_section "Network Configuration"
    
    # Attempt to automatically detect the default gateway IP using the routing table
    local sensed_ip
    sensed_ip=$(ip route show default 2>/dev/null | awk '/default/ {print $3}')
    local default_ip="${sensed_ip:-192.168.1.233}" # Fallback to 192.168.1.233 if detection fails
    
    info "Attempting to auto-detect router IP (Default Gateway)..."
    warn "If you are on WSL, the detected IP might be a virtual gateway."
    
    # Loop until a valid IP is provided or the default is accepted
    while true; do
        echo -ne "${YELLOW}  Enter Physical Router IP [Press Enter for ${CYAN}${default_ip}${YELLOW}]: ${NC}"
        read -r user_ip
        
        # Accept default if input is empty
        if [ -z "$user_ip" ]; then
            ROUTER_IP="$default_ip"
            break
        fi

        # Validate the input matches an IPv4 format using regex
        if [[ "$user_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ROUTER_IP="$user_ip"
            break
        else
            fail "Invalid input. Please enter a valid IP address (e.g., 192.168.1.233) or press Enter to accept the default."
        fi
    done
    
    # Export for use in child scripts (like stream_capture.sh)
    export ROUTER_IP
    pass "Router IP set to: $ROUTER_IP"
}

# Collects and exports Elasticsearch credentials for API health checks
configure_elk_auth() {
    print_section "ELK Stack Authentication"
    info "Elasticsearch 9.x requires credentials for API checks."
    
    echo -ne "${YELLOW}  Enter Elasticsearch username [Press Enter for 'elastic']: ${NC}"
    read -r user_input
    ES_USER="${user_input:-elastic}"
    
    # -s flag hides the password input for security
    echo -ne "${YELLOW}  Enter password for user '${ES_USER}': ${NC}"
    read -rs ES_PASS
    echo ""
    
    # Export credentials so curl commands and child processes can use them
    export ES_USER
    export ES_PASS
    pass "Credentials temporarily stored for this session."
    echo ""
}

# Resolves a host-readable CA cert for TLS-verifying the ELK stack. The stack CA
# lives inside the Elasticsearch/Logstash containers' certs volume
# (/certs/ca/ca.crt) - that path never exists on the bare host this script runs
# on, so every --cacert curl call using it as a default fails with curl exit 77
# (bad/missing CA file), which gets silenced by &>/dev/null and misreported as
# "not reachable," even when the stack is healthy. Reuses SOP-003's already-
# provisioned copy if present, otherwise self-provisions via docker cp (same
# idiom as SOP-003 above and configs/systemd/slo-metrics.service).
resolve_es_ca() {
    if [ -f "${ES_CA:-}" ] && [ -r "$ES_CA" ]; then
        info "Stack CA: $ES_CA (inherited)"
        return
    fi
    if [ -r /etc/filebeat/certs/ca.crt ]; then
        ES_CA="/etc/filebeat/certs/ca.crt"
        export ES_CA
        info "Stack CA: $ES_CA (SOP-003)"
        return
    fi
    local dest="$HOME/.config/suburban-soc/ca.crt"
    mkdir -p "$(dirname "$dest")"
    # Remove any pre-existing file/symlink at dest first so a planted symlink or
    # stale cert can't survive the copy; verify the result is actually a cert
    # before trusting it (catches a truncated copy too).
    rm -f "$dest"
    if docker cp elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt "$dest" &>/dev/null \
        && openssl x509 -in "$dest" -noout &>/dev/null; then
        chmod 0644 "$dest"
        ES_CA="$dest"
        info "Stack CA: $ES_CA (self-provisioned)"
    else
        rm -f "$dest"
        warn "Could not obtain the stack CA cert (checked /etc/filebeat/certs/ca.crt and 'docker cp elasticsearch:...') - ES/Kibana checks below will fail even if the stack is healthy"
        ES_CA="/certs/ca/ca.crt"
    fi
    export ES_CA
}

# Automates the creation and distribution of SSH keys to the remote router
setup_ssh_keys() {
    echo ""
    info "Starting automated SSH key setup..."
    local key_path="$HOME/.ssh/id_ed25519"
    
    # Check if an Ed25519 key already exists locally
    if [ ! -f "$key_path" ]; then
        info "No Ed25519 SSH key found locally. Generating one now..."
        # Generate key without a passphrase (-N "") and suppress output (-q)
        ssh-keygen -t ed25519 -f "$key_path" -N "" -q
        pass "SSH key generated at $key_path"
    else
        pass "Local SSH key already exists at $key_path"
    fi

    info "Copying public key to ${ROUTER_IP}."
    warn "You will be prompted for the router's password ONE LAST TIME."

    # Primary path: ssh-copy-id works for standard OpenSSH servers.
    # OpenWRT typically runs dropbear, where ssh-copy-id may be missing or
    # may write to a location dropbear doesn't read, so we don't treat a
    # failure here as fatal -- the fallback below handles those cases.
    if command -v ssh-copy-id &>/dev/null; then
        ssh-copy-id -i "${key_path}.pub" "${ROUTER_USER}@${ROUTER_IP}" \
            || warn "ssh-copy-id did not complete cleanly; will try OpenWRT fallback."
    else
        warn "ssh-copy-id not available; using OpenWRT-aware fallback."
    fi

    # Verify the connection works without a password using BatchMode
    if _verify_passwordless_ssh; then
        pass "Passwordless SSH successfully configured!"
        return 0
    fi

    # Fallback: manually install the key for both OpenSSH (~/.ssh/authorized_keys)
    # and dropbear/OpenWRT (/etc/dropbear/authorized_keys) layouts in one session.
    warn "Standard key copy not yet working. Trying OpenWRT/dropbear-aware install..."
    warn "You may be prompted for the router's password once more."
    _install_key_openwrt "${key_path}.pub"

    # Final verification
    if _verify_passwordless_ssh; then
        pass "Passwordless SSH successfully configured (OpenWRT fallback)!"
    else
        fail "Failed to configure passwordless SSH to ${ROUTER_IP}."
        info "Troubleshoot with: ssh -v ${ROUTER_USER}@${ROUTER_IP}"
        info "On OpenWRT, confirm dropbear allows key auth and check /etc/dropbear/authorized_keys."
        return 1
    fi
}

# Returns 0 if we can SSH to the router without a password prompt.
_verify_passwordless_ssh() {
    ssh -o ConnectTimeout=5 -o BatchMode=yes \
        "${ROUTER_USER}@${ROUTER_IP}" exit &>/dev/null
}

# Installs a public key on the router covering both OpenSSH and dropbear
# (OpenWRT) authorized_keys locations. Reads the key from the given .pub file
# via stdin so a single password-authenticated session does all the work.
# $1 = path to the public key file
_install_key_openwrt() {
    local pubkey_file="$1"

    # The remote command reads the key from stdin (fed by the .pub file).
    # ssh reads the password from /dev/tty, not stdin, so redirecting stdin
    # here does not interfere with the interactive password prompt.
    ssh -o ConnectTimeout=10 "${ROUTER_USER}@${ROUTER_IP}" '
        key="$(cat)"
        umask 077
        # Candidate locations: OpenSSH home dir and OpenWRT dropbear dir.
        for dir in "$HOME/.ssh" /etc/dropbear; do
            # Only touch /etc/dropbear if it actually exists (OpenWRT).
            if [ "$dir" = /etc/dropbear ] && [ ! -d /etc/dropbear ]; then
                continue
            fi
            mkdir -p "$dir" 2>/dev/null
            akf="$dir/authorized_keys"
            # Append only if the key is not already present (idempotent).
            if ! grep -qxF "$key" "$akf" 2>/dev/null; then
                echo "$key" >> "$akf"
            fi
            chmod 700 "$dir" 2>/dev/null
            chmod 600 "$akf" 2>/dev/null
        done
    ' < "$pubkey_file"
}

# =============================================================================
# SOP PREREQUISITE CHECKS
# =============================================================================

# Verifies all necessary services, paths, and tools are available
run_prereq_checks() {
    print_section "SOP Prerequisite Checks"
    local all_pass=true

    # Check if Docker daemon is responsive
    if docker ps &>/dev/null; then
        pass "Docker is running"
    else
        fail "Docker is not running - start Docker Desktop or: sudo service docker start"
        all_pass=false
    fi
    
    # Check if tcpdump binary is in the system PATH
    if command -v tcpdump &>/dev/null; then
        pass "tcpdump is installed"
    else
        warn "tcpdump is not installed - Local eth0 capture will fail. Run: sudo apt install tcpdump"
    fi

    # Check if we can SSH into the router without being prompted for a password
    if _verify_passwordless_ssh; then
        pass "SSH to router (${ROUTER_IP}) is reachable and authenticated"
    else
        warn "SSH to router (${ROUTER_IP}) requires a password or is unreachable."
        echo -ne "${YELLOW}  Would you like to configure passwordless SSH now? [y/N]: ${NC}"
        read -r setup_ssh
        if [[ "$setup_ssh" =~ ^[Yy]$ ]]; then
            setup_ssh_keys
        else
            warn "Remote capture scripts will not work without passwordless SSH."
        fi
    fi

    # Check if the output directory for logs exists, create it if it doesn't
    if [ -d "$LOG_DIR" ]; then
        pass "Log directory exists: $LOG_DIR"
    else
        warn "Log directory missing - creating: $LOG_DIR"
        sudo mkdir -p "$LOG_DIR"
        sudo chmod 777 "$LOG_DIR" # Ensure all users/processes can write to it
        info "Created $LOG_DIR"
    fi

    # Check if the Filebeat systemd service is active
    if systemctl is-active --quiet filebeat 2>/dev/null; then
        pass "Filebeat is running"
    else
        warn "Filebeat is not running - start with: sudo systemctl start filebeat"
    fi

    # Test Elasticsearch API connection using the provided credentials
    # Connect-timeout prevents hanging if the service is down
    resolve_es_ca
    if curl -s --cacert "$ES_CA" -u "${ES_USER}:${ES_PASS}" --connect-timeout 3 https://localhost:9200/_cluster/health &>/dev/null; then
        pass "Elasticsearch is reachable (port 9200)"
    else
        warn "Elasticsearch not reachable or auth failed - ensure ELK stack is running and password is correct."
    fi

    # Test Kibana frontend availability. #189: Kibana is TLS-only now (self-signed
    # stack CA); use the CA to securely verify reachability, mirroring es_common.sh.
    if curl -s --cacert "$ES_CA" --connect-timeout 3 https://localhost:5601 &>/dev/null; then
        pass "Kibana is reachable (port 5601)"
    else
        warn "Kibana not reachable - open https://localhost:5601 after starting ELK stack"
    fi

    echo ""
    if $all_pass; then
        echo -e "${GREEN}${BOLD}  All critical checks passed.${NC}"
    else
        echo -e "${YELLOW}${BOLD}  Some checks failed. Review warnings above before proceeding.${NC}"
    fi
}

# =============================================================================
# SOP-001-A: Live Capture - bat0 (Mesh Interface)
# =============================================================================

# Triggers remote capture on the router's mesh network interface
run_sop_001a() {
    print_section "SOP-001-A: Live Capture - bat0 (Mesh Interface)"
    info "Router: ${ROUTER_USER}@${ROUTER_IP}"
    info "Interface: bat0"
    info "Output: $LOG_DIR"
    info "Press Ctrl+C to stop capture"
    confirm || return # Abort if user doesn't confirm

    # Ensure the helper script is executable, then run it
    chmod +x "${SCRIPT_DIR}/stream_capture.sh"
    echo -e "\n${GREEN}Starting bat0 capture...${NC}\n"
    "${SCRIPT_DIR}/stream_capture.sh" bat0
}

# =============================================================================
# SOP-001-B: Live Capture - br-lan (Standard LAN Bridge)
# =============================================================================

# Triggers remote capture on the router's local bridge interface
run_sop_001b() {
    print_section "SOP-001-B: Live Capture - br-lan (LAN Bridge)"
    info "Router: ${ROUTER_USER}@${ROUTER_IP}"
    info "Interface: br-lan"
    info "Output: $LOG_DIR"
    info "Press Ctrl+C to stop capture"
    confirm || return

    chmod +x "${SCRIPT_DIR}/stream_capture.sh"
    echo -e "\n${GREEN}Starting br-lan capture...${NC}\n"
    "${SCRIPT_DIR}/stream_capture.sh" br-lan
}

# =============================================================================
# SOP-001-C: Live Capture - eth0 (Local Host)
# =============================================================================

# Triggers a local capture on the machine running the script
run_sop_001c() {
    print_section "SOP-001-C: Live Capture - Local eth0"
    info "Interface: eth0 (local WSL/host)"
    info "Output: $LOG_DIR"
    warn "Requires sudo"
    info "Press Ctrl+C to stop capture"
    confirm || return

    chmod +x "${SCRIPT_DIR}/stream_capture.sh"
    echo -e "\n${GREEN}Starting eth0 capture...${NC}\n"
    # Local captures usually require elevated privileges to access network interfaces
    sudo "${SCRIPT_DIR}/stream_capture.sh" raw
}

# =============================================================================
# SOP-001-D: Offline PCAP Analysis
# =============================================================================

# Processes an existing .pcap file through Zeek
run_sop_001d() {
    print_section "SOP-001-D: Offline PCAP Analysis"
    # Fallback to a default path if PCAP_FILE is not pre-set in the environment
    PCAP_FILE="${PCAP_FILE:-/storage/PCAP/http.pcap}"

    # Prompt user for a path if the default doesn't exist
    if [ ! -f "$PCAP_FILE" ]; then
        fail "PCAP file not found: $PCAP_FILE"
        echo -ne "  Enter full path to your PCAP file: "
        read -r PCAP_FILE
        if [ ! -f "$PCAP_FILE" ]; then
            fail "File not found. Aborting."
            return 1 # Exit function with error code
        fi
    fi

    info "PCAP file: $PCAP_FILE"
    info "Output: $LOG_DIR"
    confirm || return

    chmod +x "${SCRIPT_DIR}/zeek_run_pcap.sh"
    echo -e "\n${GREEN}Running Zeek on PCAP...${NC}\n"
    # Pass the selected file to the analysis script via environment variable
    PCAP_FILE="$PCAP_FILE" "${SCRIPT_DIR}/zeek_run_pcap.sh"
    echo -e "\n${GREEN}Analysis complete. Check $LOG_DIR for output files.${NC}"
}

# =============================================================================
# SOP-001-E: Interactive Zeek Host Monitor
# =============================================================================

# Drops the user into an interactive Zeek monitoring session locally
run_sop_001e() {
    print_section "SOP-001-E: Interactive Zeek Host Monitor"
    info "Interface: eth0 (host network mode)"
    info "Output: $LOG_DIR"
    warn "Requires sudo"
    info "Press Ctrl+C to stop"
    confirm || return

    chmod +x "${SCRIPT_DIR}/zeek_connect_host.sh"
    echo -e "\n${GREEN}Starting interactive Zeek...${NC}\n"
    sudo "${SCRIPT_DIR}/zeek_connect_host.sh"
}

# =============================================================================
# SOP-002: Filebeat - Install & Configure
# =============================================================================

# Installs and appends Zeek log ingestion configurations to Filebeat
run_sop_002() {
    print_section "SOP-002: Filebeat - Install & Configure"

    # Avoid reinstalling if it's already running, unless the user forces it
    if systemctl is-active --quiet filebeat 2>/dev/null; then
        pass "Filebeat is already installed and running"
        echo -ne "  Reinstall anyway? [y/N]: "
        read -r choice
        [[ "$choice" =~ ^[Yy]$ ]] || return
    fi

    info "Installing Filebeat 9.x via Elastic APT repository"
    warn "Requires sudo"
    confirm || return

    chmod +x "${SCRIPT_DIR}/install_filebeat.sh"
    sudo "${SCRIPT_DIR}/install_filebeat.sh"

    echo ""
    info "Configuring Filebeat to watch Zeek logs and output to Logstash..."
    local FILEBEAT_CONFIG="/etc/filebeat/filebeat.yml"
    local AUTHORITATIVE_CONFIG="${SCRIPT_DIR}/../../configs/network/filebeat.yml"
    local FILEBEAT_CERT_DIR="/etc/filebeat/certs"
    local SRC_CERTS="/usr/share/logstash/config/certs"

    # Provision the stack CA + Filebeat client cert/key for the Logstash Beats mTLS
    # handshake. Missing CA -> ssl.enabled fails with EOF; missing client cert ->
    # Logstash rejects the batch with "tls: certificate required". All three live in
    # the stack certs volume, reachable through the logstash container (docker cp runs
    # as the daemon, so it reads them even though logstash runs as uid 1000).
    info "Provisioning Filebeat TLS material to ${FILEBEAT_CERT_DIR}"
    sudo mkdir -p "$FILEBEAT_CERT_DIR"
    for f in ca/ca.crt filebeat/filebeat.crt filebeat/filebeat.key; do
        local base; base="$(basename "$f")"
        local dest="${FILEBEAT_CERT_DIR}/${base}"
        if [ ! -f "$dest" ]; then
            if docker cp "logstash:${SRC_CERTS}/${f}" "/tmp/soc_${base}" 2>/dev/null; then
                sudo mv "/tmp/soc_${base}" "$dest"
            else
                warn "Could not copy ${f} from the 'logstash' container — place it at ${dest} manually"
            fi
        fi
    done
    # CA and client cert are public (644); the private key is root-only (600).
    sudo chown root:root "${FILEBEAT_CERT_DIR}"/* 2>/dev/null || true
    sudo chmod 644 "${FILEBEAT_CERT_DIR}/ca.crt" "${FILEBEAT_CERT_DIR}/filebeat.crt" 2>/dev/null || true
    sudo chmod 600 "${FILEBEAT_CERT_DIR}/filebeat.key" 2>/dev/null || true
    pass "Filebeat TLS material installed in ${FILEBEAT_CERT_DIR}"

    # Install the authoritative, TLS-enabled config by OVERWRITE (not append).
    # The old heredoc used `tee -a`, which on a second run duplicated the
    # filebeat.inputs/output.logstash keys and broke Filebeat startup. The repo
    # config at configs/network/filebeat.yml is the single source of truth.
    if [ -f "$AUTHORITATIVE_CONFIG" ]; then
        [ -f "$FILEBEAT_CONFIG" ] && sudo cp "$FILEBEAT_CONFIG" "${FILEBEAT_CONFIG}.stock.bak"
        sudo cp "$AUTHORITATIVE_CONFIG" "$FILEBEAT_CONFIG"
        sudo chmod 0644 "$FILEBEAT_CONFIG"
        pass "Filebeat config installed from configs/network/filebeat.yml (TLS-enabled)"
    else
        warn "Authoritative config not found at $AUTHORITATIVE_CONFIG - apply config manually"
    fi

    # Enable at boot and start the service
    sudo systemctl enable filebeat
    sudo systemctl start filebeat
    sudo systemctl status filebeat --no-pager
    pass "Filebeat enabled and started"
}

# =============================================================================
# SOP-004: Clear Logs
# =============================================================================

# Destructive action: Wipes local Zeek logs to start a fresh capture session
run_sop_004() {
    print_section "SOP-004: Clear Logs - Reset Environment"
    warn "This will PERMANENTLY DELETE all files in $LOG_DIR"
    warn "Ensure Filebeat has already shipped logs to Elasticsearch"
    echo ""

    # Force the user to type "CONFIRM" to prevent accidental data loss
    echo -ne "${RED}  Type 'CONFIRM' to proceed: ${NC}"
    read -r choice
    if [ "$choice" != "CONFIRM" ]; then
        info "Aborted."
        return
    fi

    chmod +x "${SCRIPT_DIR}/clear_logs.sh"
    sudo "${SCRIPT_DIR}/clear_logs.sh"
    pass "Logs cleared: $LOG_DIR"
}

# =============================================================================
# SOP-005: End-to-End Pipeline Startup
# =============================================================================

# Guided wizard combining checks, service startup, and a capture selection
run_sop_005() {
    print_section "SOP-005: End-to-End Pipeline Startup"
    info "This will walk through the full pipeline startup sequence"
    confirm || return

    echo ""
    echo -e "${BOLD}Step 1: Verify Docker is running${NC}"
    if docker ps &>/dev/null; then
        pass "Docker is running"
    else
        fail "Docker not running. Start Docker Desktop or: sudo service docker start"
        return 1
    fi

    echo -e "\n${BOLD}Step 2: ELK Stack${NC}"
    # Wait for the user to manually start ELK if it isn't already responsive
    resolve_es_ca
    if curl -s --cacert "$ES_CA" -u "${ES_USER}:${ES_PASS}" --connect-timeout 3 https://localhost:9200/_cluster/health &>/dev/null; then
        pass "Elasticsearch already up"
    else
        warn "Elasticsearch not reachable. Start your ELK stack (docker compose up -d)"
        echo -ne "  Press Enter once ELK is running..."
        read -r
        # Re-resolve: a cold start (ELK/its containers not up yet at the first
        # call above) can leave ES_CA latched on the broken fallback from
        # resolve_es_ca's last branch. Now that the user has confirmed ELK is
        # actually up, clear it and retry so Steps 3-4 don't inherit a stale
        # failure.
        unset ES_CA
        resolve_es_ca
    fi

    echo -e "\n${BOLD}Step 3: Verify Elasticsearch${NC}"
    # Parse the specific 'status' field from the JSON health response
    ES_STATUS=$(curl -s --cacert "$ES_CA" -u "${ES_USER}:${ES_PASS}" https://localhost:9200/_cluster/health | grep -o '"status":"[^"]*"' | head -1)
    if [ -n "$ES_STATUS" ]; then
        pass "Elasticsearch: $ES_STATUS"
    else
        warn "Could not read Elasticsearch status - verify your password is correct."
    fi

    echo -e "\n${BOLD}Step 4: Verify Kibana${NC}"
    # #189: Kibana is TLS-only now (self-signed stack CA); verify using CA.
    if curl -s --cacert "$ES_CA" --connect-timeout 5 https://localhost:5601 &>/dev/null; then
        pass "Kibana reachable at https://localhost:5601"
    else
        warn "Kibana not reachable - check Docker containers"
    fi

    echo -e "\n${BOLD}Step 5: Start Filebeat${NC}"
    if ! systemctl is-active --quiet filebeat 2>/dev/null; then
        sudo systemctl start filebeat
        pass "Filebeat started"
    else
        pass "Filebeat already running"
    fi

    # Sub-menu to choose the actual data collection method
    echo -e "\n${BOLD}Step 6: Select Capture Mode${NC}"
    echo -e "  ${CYAN}[A]${NC} Live capture - bat0 (mesh)"
    echo -e "  ${CYAN}[B]${NC} Live capture - br-lan"
    echo -e "  ${CYAN}[C]${NC} Live capture - eth0 (local)"
    echo -e "  ${CYAN}[D]${NC} Offline PCAP analysis"
    echo -ne "  Select [A/B/C/D]: "
    read -r cap_choice

    # Execute the corresponding function based on selection (^^ converts input to uppercase)
    case "${cap_choice^^}" in
        A) run_sop_001a ;;
        B) run_sop_001b ;;
        C) run_sop_001c ;;
        D) run_sop_001d ;;
        *) warn "No capture selected" ;;
    esac

    echo -e "\n${BOLD}Step 7: Verify logs flowing${NC}"
    # Count the number of files generated in the log directory
    LOG_COUNT=$(ls "$LOG_DIR" 2>/dev/null | wc -l)
    if [ "$LOG_COUNT" -gt 0 ]; then
        pass "$LOG_COUNT log files found in $LOG_DIR"
        ls "$LOG_DIR"
    else
        warn "No log files yet in $LOG_DIR - capture may still be running"
    fi

    echo -e "\n${BOLD}Step 8: Confirm data in Kibana${NC}"
    info "Open Kibana -> Discover -> Index pattern: logstash-*"
    info "URL: https://localhost:5601"
    pass "Pipeline startup sequence complete"
}

# =============================================================================
# MAIN MENU
# =============================================================================

# Central routing hub for the script
main_menu() {
    print_header
    
    # Run mandatory configurations immediately upon script start
    configure_router_ip
    configure_elk_auth
    run_prereq_checks

    # Infinite loop to keep the menu active until explicitly exited
    while true; do
        echo ""
        print_section "Select SOP to Execute"
        echo -e "  ${CYAN}[1]${NC} SOP-001-A - Live Capture: bat0 (mesh interface)"
        echo -e "  ${CYAN}[2]${NC} SOP-001-B - Live Capture: br-lan (LAN bridge)"
        echo -e "  ${CYAN}[3]${NC} SOP-001-C - Live Capture: eth0 (local host)"
        echo -e "  ${CYAN}[4]${NC} SOP-001-D - Offline PCAP Analysis"
        echo -e "  ${CYAN}[5]${NC} SOP-001-E - Interactive Zeek Host Monitor"
        echo -e "  ${CYAN}[6]${NC} SOP-002   - Install & Configure Filebeat"
        echo -e "  ${CYAN}[7]${NC} SOP-004   - Clear Logs (Reset Environment)"
        echo -e "  ${CYAN}[8]${NC} SOP-005   - Full End-to-End Pipeline Startup"
        echo -e "  ${CYAN}[9]${NC} Re-run Prerequisite Checks"
        echo -e "  ${CYAN}[Q]${NC} Quit"
        echo ""
        echo -ne "${YELLOW}  Enter choice: ${NC}"
        read -r choice

        # Dispatch user input to the correct function
        case "$choice" in
            1) run_sop_001a ;;
            2) run_sop_001b ;;
            3) run_sop_001c ;;
            4) run_sop_001d ;;
            5) run_sop_001e ;;
            6) run_sop_002  ;;
            7) run_sop_004  ;;
            8) run_sop_005  ;;
            9) run_prereq_checks ;;
            [Qq]) echo -e "\n${CYAN}Exiting Suburban-SOC Pipeline Automation.${NC}\n"; exit 0 ;;
            *) warn "Invalid choice - select 1-9 or Q" ;;
        esac
    done
}

# --- Entry Point ---
# Start the script by invoking the main menu
main_menu