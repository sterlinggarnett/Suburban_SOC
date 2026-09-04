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

# #389: Zeek 8.1.0 introduced Log::default_max_field_string_bytes - a per-
# string BYTE cap the log writer applies to EVERY logged string field,
# container elements included, silently cutting the value and recording the
# cut only as a connection-less weird (log_string_field_truncated, addl =
# the stream name, no uid) plus a telemetry counter. Upstream default 4096 -
# the "no marker anywhere in dns.log" #389 live-observed on the pinned 8.2.1
# image. Raised here to 8191: EXACTLY dns.answers' ignore_above in
# configs/elasticsearch/logstash-security-template.json, deliberately not
# higher. Security-auditor review of a 16384 first draft found that any cap
# ABOVE the indexing ceiling opens a detection blind window - a Zeek-logged
# TXT answer in (8191, cap] is stored but never indexed, so
# net_zeek_dns_txt_answer_abuse.yml's answers|re can no longer match it -
# whereas the old 4096 cut, for all its silence, kept every answer
# indexable. Pinned to the ceiling, retained content doubles and every
# Zeek-logged answer stays rule-matchable; a Zeek-truncated answer lands at
# exactly 8191 bytes, is still indexed, and is the number
# configs/logstash.conf's pipeline.dns_answer_truncated_by_zeek check keys
# on (metered with a target of 0 by slo_metrics.py, alongside the weird
# count). Raising both ceilings together past 8191 needs the array-aware
# byte clamp the template's own _meta WARNING names - #545, not done here.
# Global rather than DNS::LOG-only: the Stream record carries per-stream
# limits but only at create_stream time, so a per-stream override means
# tearing down and recreating a base stream from here - more fragile than
# one documented redef, and every other stream's long strings already meet
# the same ignore_above/byte-clamp ceilings downstream (#367's CI gate).
# The per-record total, Log::default_max_total_string_bytes, stays at its
# 256000-byte upstream default (pinned on the real image by
# tests/detections/test_zeek_log_field_string_cap_live.py, which also pins
# the upstream 4096 default and this redef's exact effect);
# tests/pipeline/test_zeek_log_field_string_cap.py pins this value, the
# template ceiling, logstash.conf's literal and test_field_truncation.py's
# mirror constant to each other.
# Version-guarded: a pre-8.1 Zeek has no such identifier and rejects the
# whole file - `"redef" used but not previously defined
# (Log::default_max_field_string_bytes)`, live-confirmed on a host-native
# 8.0.5 - which would take every @load above down with it. All four real
# capture paths' post-copy staleness guards (#288) grep for this exact
# redef line, value included, so a stale or hand-edited copy of this file
# refuses to start rather than running at a different cap unnoticed.
@if ( Version::number >= 80100 )
redef Log::default_max_field_string_bytes = 8191;
@endif
