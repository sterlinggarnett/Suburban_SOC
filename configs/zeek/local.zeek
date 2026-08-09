# Zeek local.zeek configuration
#
# #286: this file is NOT loaded by any real capture invocation (every
# script under scripts/setup/ and configs/systemd/zeek-host-capture.service
# passes /data/intel/config.zeek instead) — confirmed by grepping every
# capture entry point in the repo. The mac-logging @load that used to sit
# here (closed as shipped in #63-72) never actually ran; source.mac was
# silently empty in every real SOAR quarantine case since. The real fix now
# lives in configs/intel/config.zeek, the file every capture invocation
# actually loads. Left here as dead config rather than deleted — this file
# still has other content below unrelated to #286, out of that issue's scope.

@load base/protocols/conn

# Suburban-SOC — Network Dashboard (Component 2): TLS/SSL telemetry
#
# Generates ssl.log with server_name (SNI), cipher, curve, version, and
# validation_status fields, feeding the SNI / cipher-suite / TLS-audit
# panels on the Network & Traffic dashboard. Boundary HTTP scope keeps
# ssl.log volume manageable; monitor disk if mesh traffic is heavy.
@load base/protocols/ssl
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/log-hostcerts-only

# Suburban-SOC — WS1.4: passive asset inventory (NIST Identify)
#
# The asset inventory is derived from conn.log (source.ip + source.mac) on the
# Asset Inventory dashboard — see configs/server/asset_inventory.ndjson. MAC
# enrichment happens in configs/intel/config.zeek (#286), the file the real
# capture path actually loads, NOT in this dead file — see this file's own
# header. We deliberately do NOT enable
# known-hosts/known-services: Zeek's `host` field (the asset IP) collides with the
# ECS/Filebeat `host` object and is clobbered before it reaches Logstash, so it
# can't reliably populate asset.ip. Revisit once Filebeat preserves Zeek's `host`
# (rename it pre-host-metadata) — see docs/detections/suricata-evaluation.md style note.

# =============================================================================
# Suburban-SOC — WS3.4: privacy & data minimization (capture-scope limits)
#
# SOC 2 Privacy / data-handling: capture metadata for detection, NOT user content.
# The single strongest privacy control is at the sensor — data Zeek never writes
# can never be stored, snapshotted, or subject to erasure. See docs/SOP-012.
# =============================================================================

# 1) NO packet payloads. We never reassemble or log raw stream content. These are
#    core Zeek tuning consts (always defined); F = do not deliver full byte streams.
redef tcp_content_deliver_all_orig = F;
redef tcp_content_deliver_all_resp = F;
redef udp_content_deliver_all_orig = F;
redef udp_content_deliver_all_resp = F;

# 2) Do NOT extract or carve files off the wire. We deliberately do NOT
#    `@load base/files/extract` (the file-extraction framework) — without it, no
#    payload is ever written to disk. Keep it that way; do not add that @load.

# 3) HTTP: keep request method/host/status (security-relevant); never log
#    basic-auth passwords. Bodies and cookie/authorization headers are not part of
#    Zeek's default http.log, and the logstash pipeline (WS3.4) drops them again
#    defensively if any source emits them.
@load base/protocols/http
redef HTTP::default_capture_password = F;     # never log basic-auth passwords

# 4) DNS: queries are security signal (C2/exfil); keep them. No additional PII.
@load base/protocols/dns

# NOTE: retention of what IS captured is bounded by ILM (WS0.5) + the per-tenant
# right-to-erasure path (scripts/setup/erase_tenant.sh). Capture scope (here) +
# retention limit (ILM) + erasure (script) are the three data-handling controls.
