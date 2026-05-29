# Zeek local.zeek configuration
# Suburban-SOC — Phase A: MAC Address Enrichment (SOAR Integration)
#
# Load MAC address logging so that orig_l2_addr and resp_l2_addr
# are appended to zeek.conn logs, enabling device-level quarantine
# by MAC address rather than IP (which can be spoofed or rotated via DHCP).

@load base/protocols/conn
@load policy/protocols/conn/mac-logging

# Suburban-SOC — Network Dashboard (Component 2): TLS/SSL telemetry
#
# Generates ssl.log with server_name (SNI), cipher, curve, version, and
# validation_status fields, feeding the SNI / cipher-suite / TLS-audit
# panels on the Network & Traffic dashboard. Boundary HTTP scope keeps
# ssl.log volume manageable; monitor disk if mesh traffic is heavy.
@load base/protocols/ssl
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/log-hostcerts-only
