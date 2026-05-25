# Zeek local.zeek configuration
# Suburban-SOC — Phase A: MAC Address Enrichment (SOAR Integration)
#
# Load MAC address logging so that orig_l2_addr and resp_l2_addr
# are appended to zeek.conn logs, enabling device-level quarantine
# by MAC address rather than IP (which can be spoofed or rotated via DHCP).

@load base/protocols/conn
@load policy/protocols/conn/mac-logging
