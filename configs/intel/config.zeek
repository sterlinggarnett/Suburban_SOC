@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

# #228 (M13 US5): SSL cert-chain validation is a policy script, not part of
# Zeek's default (non-bare) auto-load set, so ssl.log's validation_status
# field does not exist without this — confirmed empirically (`print
# SSL::validate_certs` fails with "unknown identifier" before this @load).
# Needed for net_zeek_ssl_self_signed_c2 / net_zeek_ssl_expired_cert_connection.
@load policy/protocols/ssl/validate-certs

# base/protocols/smtp is part of Zeek's default (non-bare) auto-load set
# (base/init-default.zeek) - confirmed empirically (`print SMTP::LOG`
# succeeds without any explicit @load). No change needed for #240's SMTP
# rules to have a log source; only the ECS/pySigma field mapping is missing,
# and that's rule-specific work deferred to the phase that writes those
# rules, not a collection gap to fix here.
#
# NOT fixed here, deliberately: mac-logging (orig_l2_addr/resp_l2_addr ->
# source.mac/destination.mac) was closed as shipped in #63-72 but only ever
# added to configs/zeek/local.zeek, which no real capture invocation loads -
# source.mac has been silently empty in every SOAR quarantine case record
# and Discord notification since. Loading the script alone doesn't fix that:
# the field lands on conn.log, but the SOAR body is built from zeek.intel
# matches (configs/logstash.conf's zeek.intel branch), and nothing joins the
# two logs by `uid`. Shipping the @load without that join would add new
# per-connection device-identifier (MAC) collection - personal data under
# SOP-012 - for zero behavior change. That's a real, separate fix (uid-keyed
# conn<->intel correlation, plus a SOP-012 data-inventory update); tracked
# for its own issue rather than half-done here.
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
