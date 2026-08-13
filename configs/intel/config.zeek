@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

# #228 (M13 US5): SSL cert-chain validation is a policy script, not part of
# Zeek's default (non-bare) auto-load set, so ssl.log's validation_status
# field does not exist without this — confirmed empirically (`print
# SSL::validate_certs` fails with "unknown identifier" before this @load).
# Needed for net_zeek_ssl_self_signed_c2 / net_zeek_ssl_expired_cert_connection.
@load policy/protocols/ssl/validate-certs

# #288: capture-loss is a policy script too, same situation as validate-
# certs above — not in Zeek's default auto-load set, so capture_loss.log
# does not exist without this. validate-certs adds real per-connection
# OpenSSL cert-chain verification with no aggregate resource guard; a burst
# of unique/large chains could show up as CPU pressure, and the real
# capture path (zeek-host-capture.service: tcpdump | docker run zeek -r -)
# has no load shedding, so that pressure surfaces as packet drops — a blind
# spot across every protocol, not just TLS. This makes percent_lost a
# measurable, alertable signal (scripts/setup/ai_agent/slo_metrics.py's
# capture_loss_max_pct) instead of a log nobody reads.
@load policy/misc/capture-loss

# base/protocols/smtp is part of Zeek's default (non-bare) auto-load set
# (base/init-default.zeek) - confirmed empirically (`print SMTP::LOG`
# succeeds without any explicit @load). No change needed for #240's SMTP
# rules to have a log source; only the ECS/pySigma field mapping is missing,
# and that's rule-specific work deferred to the phase that writes those
# rules, not a collection gap to fix here.
#
# #286: mac-logging (orig_l2_addr/resp_l2_addr -> source.mac/destination.mac)
# was closed as shipped in #63-72 but only ever added to configs/zeek/
# local.zeek, which no real capture invocation loads - source.mac has been
# silently empty in every SOAR quarantine case record and Discord
# notification since. Loading it here (the real capture path) is now safe:
# configs/logstash.conf's Category 0 branch renames orig_l2_addr/
# resp_l2_addr onto conn.log's source.mac/destination.mac, AND its
# zeek.intel branch now does a uid-keyed lookup against that same tenant's
# conn.log records to get the MAC onto the record that actually triggers
# SOAR containment (intel.log itself never carries L2 addresses). Also
# updated: docs/SOP-012-privacy-data-handling.md's data inventory now lists
# MAC addresses as personal data this pipeline collects.
@load policy/protocols/conn/mac-logging
redef Intel::read_files += { "/data/intel/intel.dat" };

# Suspend packet processing until the Intel framework finishes reading the feed asynchronously
event zeek_init() &priority=-10 {
    suspend_processing();
}

event Input::end_of_data(name: string, source: string) {
    if ( source == "/data/intel/intel.dat" ) {
        continue_processing();
    }
}
