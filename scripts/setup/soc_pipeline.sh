#!/bin/bash
# =============================================================================
# Suburban-SOC Pipeline Automation Script
# SOP Reference: docs/SOP-001-pipeline-operations.md
# Owner: Tommy Lammers (@voltron-1) - Security Analyst / Manager
# Version: 1.1 | CIS 3353 Spring 2026
# =============================================================================

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# SETUP_DIR = the directory containing this script (scripts/setup/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/storage/PCAP/zeek_logs"
ROUTER_IP="${ROUTER_IP:-10.18.81.1}"
ROUTER_USER="${ROUTER_USER:-root}"

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

print_header() {
    echo -e "\n${CYAN}${BOLD}============================================${NC}"
    echo -e "${CYAN}${BOLD}  Suburban-SOC Pipeline Automation${NC}"
    echo -e "${CYAN}${BOLD}  CIS 3353 | Spring 2026${NC}"
    echo -e "${CYAN}${BOLD}============================================${NC}\n"
}

print_section() {
    echo -e "\n${BOLD}>>> $1${NC}"
    echo -e "${CYAN}--------------------------------------------${NC}"
}

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }

confirm() {
    read -rp "$(echo -e "${YELLOW}  Proceed? [y/N]: ${NC}")" choice
    [[ "$choice" =~ ^[Yy]$ ]]
}

# =============================================================================
# SOP PREREQUISITE CHECKS
# =============================================================================

run_prereq_checks() {
    print_section "SOP Prerequisite Checks"
    local all_pass=true

    # Check Docker
    if docker ps &>/dev/null; then
        pass "Docker is running"
    else
        fail "Docker is not running - start Docker Desktop or: sudo service docker start"
        all_pass=false
    fi

    # Check SSH to router
    if ssh -o ConnectTimeout=5 -o BatchMode=yes "${ROUTER_USER}@${ROUTER_IP}" exit &>/dev/null; then
        pass "SSH to router (${ROUTER_IP}) is reachable"
    else
        warn "SSH to router (${ROUTER_IP}) unreachable - remote capture scripts will not work"
    fi

    # Check log directory
    if [ -d "$LOG_DIR" ]; then
        pass "Log directory exists: $LOG_DIR"
    else
        warn "Log directory missing - creating: $LOG_DIR"
        sudo mkdir -p "$LOG_DIR"
        sudo chmod 777 "$LOG_DIR"
        info "Created $LOG_DIR"
    fi

    # Check Filebeat
    if systemctl is-active --quiet filebeat 2>/dev/null; then
        pass "Filebeat is running"
    else
        warn "Filebeat is not running - start with: sudo systemctl start filebeat"
    fi

    # Check Elasticsearch
    if curl -s --connect-timeout 3 http://localhost:9200 &>/dev/null; then
        pass "Elasticsearch is reachable (port 9200)"
    else
        warn "Elasticsearch not reachable - ensure ELK stack is running"
    fi

    # Check Kibana
    if curl -s --connect-timeout 3 http://localhost:5601 &>/dev/null; then
        pass "Kibana is reachable (port 5601)"
    else
        warn "Kibana not reachable - open http://localhost:5601 after starting ELK stack"
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

run_sop_001a() {
    print_section "SOP-001-A: Live Capture - bat0 (Mesh Interface)"
    info "Router: ${ROUTER_USER}@${ROUTER_IP}"
    info "Interface: bat0"
    info "Output: $LOG_DIR"
    info "Press Ctrl+C to stop capture"
    confirm || return

    chmod +x "${SCRIPT_DIR}/stream_bat0_data.sh"
    echo -e "\n${GREEN}Starting bat0 capture...${NC}\n"
    "${SCRIPT_DIR}/stream_bat0_data.sh"
}

# =============================================================================
# SOP-001-B: Live Capture - br-lan (Standard LAN Bridge)
# =============================================================================

run_sop_001b() {
    print_section "SOP-001-B: Live Capture - br-lan (LAN Bridge)"
    info "Router: ${ROUTER_USER}@${ROUTER_IP}"
    info "Interface: br-lan"
    info "Output: $LOG_DIR"
    info "Press Ctrl+C to stop capture"
    confirm || return

    chmod +x "${SCRIPT_DIR}/stream_br_lan_data.sh"
    echo -e "\n${GREEN}Starting br-lan capture...${NC}\n"
    "${SCRIPT_DIR}/stream_br_lan_data.sh"
}

# =============================================================================
# SOP-001-C: Live Capture - eth0 (Local Host)
# =============================================================================

run_sop_001c() {
    print_section "SOP-001-C: Live Capture - Local eth0"
    info "Interface: eth0 (local WSL/host)"
    info "Output: $LOG_DIR"
    warn "Requires sudo"
    info "Press Ctrl+C to stop capture"
    confirm || return

    chmod +x "${SCRIPT_DIR}/stream_raw_data.sh"
    echo -e "\n${GREEN}Starting eth0 capture...${NC}\n"
    sudo "${SCRIPT_DIR}/stream_raw_data.sh"
}

# =============================================================================
# SOP-001-D: Offline PCAP Analysis
# =============================================================================

run_sop_001d() {
    print_section "SOP-001-D: Offline PCAP Analysis"
    PCAP_FILE="${PCAP_FILE:-/storage/PCAP/http.pcap}"

    if [ ! -f "$PCAP_FILE" ]; then
        fail "PCAP file not found: $PCAP_FILE"
        read -rp "  Enter full path to your PCAP file: " PCAP_FILE
        if [ ! -f "$PCAP_FILE" ]; then
            fail "File not found. Aborting."
            return 1
        fi
    fi

    info "PCAP file: $PCAP_FILE"
    info "Output: $LOG_DIR"
    confirm || return

    chmod +x "${SCRIPT_DIR}/zeek_run_pcap.sh"
    echo -e "\n${GREEN}Running Zeek on PCAP...${NC}\n"
    PCAP_FILE="$PCAP_FILE" "${SCRIPT_DIR}/zeek_run_pcap.sh"
    echo -e "\n${GREEN}Analysis complete. Check $LOG_DIR for output files.${NC}"
}

# =============================================================================
# SOP-001-E: Interactive Zeek Host Monitor
# =============================================================================

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

run_sop_002() {
    print_section "SOP-002: Filebeat - Install & Configure"

    if systemctl is-active --quiet filebeat 2>/dev/null; then
        pass "Filebeat is already installed and running"
        read -rp "  Reinstall anyway? [y/N]: " choice
        [[ "$choice" =~ ^[Yy]$ ]] || return
    fi

    info "Installing Filebeat 8.x via Elastic APT repository"
    warn "Requires sudo"
    confirm || return

    chmod +x "${SCRIPT_DIR}/install_filebeat.sh"
    sudo "${SCRIPT_DIR}/install_filebeat.sh"

    echo ""
    info "Configuring Filebeat to watch Zeek logs and output to Logstash..."
    local FILEBEAT_CONFIG="/etc/filebeat/filebeat.yml"

    if [ -f "$FILEBEAT_CONFIG" ]; then
        sudo tee -a "$FILEBEAT_CONFIG" > /dev/null <<'FBEOF'

# --- Suburban-SOC Zeek Integration ---
filebeat.inputs:
  - type: filestream
    id: zeek-logs
    paths:
      - /storage/PCAP/zeek_logs/*.log
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true

output.logstash:
  hosts: ["localhost:5044"]
FBEOF
        pass "Filebeat config updated"
    else
        warn "filebeat.yml not found at $FILEBEAT_CONFIG - apply config manually"
    fi

    sudo systemctl enable filebeat
    sudo systemctl start filebeat
    sudo systemctl status filebeat --no-pager
    pass "Filebeat enabled and started"
}

# =============================================================================
# SOP-004: Clear Logs
# =============================================================================

run_sop_004() {
    print_section "SOP-004: Clear Logs - Reset Environment"
    warn "This will PERMANENTLY DELETE all files in $LOG_DIR"
    warn "Ensure Filebeat has already shipped logs to Elasticsearch"
    echo ""

    read -rp "$(echo -e "${RED}  Type 'CONFIRM' to proceed: ${NC}")" choice
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
    if curl -s --connect-timeout 3 http://localhost:9200 &>/dev/null; then
        pass "Elasticsearch already up"
    else
        warn "Elasticsearch not reachable. Start your ELK stack (docker compose up -d)"
        read -rp "  Press Enter once ELK is running..."
    fi

    echo -e "\n${BOLD}Step 3: Verify Elasticsearch${NC}"
    ES_STATUS=$(curl -s http://localhost:9200 | grep -o '"status":"[^"]*"' | head -1)
    if [ -n "$ES_STATUS" ]; then
        pass "Elasticsearch: $ES_STATUS"
    else
        warn "Could not read Elasticsearch status"
    fi

    echo -e "\n${BOLD}Step 4: Verify Kibana${NC}"
    if curl -s --connect-timeout 5 http://localhost:5601 &>/dev/null; then
        pass "Kibana reachable at http://localhost:5601"
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

    echo -e "\n${BOLD}Step 6: Select Capture Mode${NC}"
    echo -e "  ${CYAN}[A]${NC} Live capture - bat0 (mesh)"
    echo -e "  ${CYAN}[B]${NC} Live capture - br-lan"
    echo -e "  ${CYAN}[C]${NC} Live capture - eth0 (local)"
    echo -e "  ${CYAN}[D]${NC} Offline PCAP analysis"
    read -rp "  Select [A/B/C/D]: " cap_choice

    case "${cap_choice^^}" in
        A) run_sop_001a ;;
        B) run_sop_001b ;;
        C) run_sop_001c ;;
        D) run_sop_001d ;;
        *) warn "No capture selected" ;;
    esac

    echo -e "\n${BOLD}Step 7: Verify logs flowing${NC}"
    LOG_COUNT=$(ls "$LOG_DIR" 2>/dev/null | wc -l)
    if [ "$LOG_COUNT" -gt 0 ]; then
        pass "$LOG_COUNT log files found in $LOG_DIR"
        ls "$LOG_DIR"
    else
        warn "No log files yet in $LOG_DIR - capture may still be running"
    fi

    echo -e "\n${BOLD}Step 8: Confirm data in Kibana${NC}"
    info "Open Kibana -> Discover -> Index pattern: logstash-*"
    info "URL: http://localhost:5601"
    pass "Pipeline startup sequence complete"
}

# =============================================================================
# MAIN MENU
# =============================================================================

main_menu() {
    print_header
    run_prereq_checks

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
        read -rp "$(echo -e "${YELLOW}  Enter choice: ${NC}")" choice

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
main_menu
