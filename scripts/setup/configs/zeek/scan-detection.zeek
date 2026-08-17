##! Minimal port-scan detection for Suburban-SOC (Issue #22, task 1).
##!
##! Modern Zeek no longer ships the legacy Scan framework, so a SYN sweep
##! produces conn.log rows but never a `Scan::Port_Scan` notice — which is the
##! exact signal the validation harness (tests/anomaly_simulation) and the
##! Executive dashboard's MITRE T1046 mapping key on.
##!
##! This script restores that signal: it counts the distinct destination ports
##! each source touches within a window and raises one `Scan::Port_Scan` notice
##! once a source crosses the threshold.
##!
##! Load it alongside the site policy, e.g.:
##!   sudo /opt/zeek/bin/zeek -C -i lo Log::default_logdir=/storage/PCAP/zeek_logs \
##!        LogAscii::use_json=T local \
##!        /home/<you>/projects/Suburban-SOC/scripts/setup/configs/zeek/scan-detection.zeek
##!
##! #331 investigated tightening this script against a spoofed-source
##! metric-gaming concern and rejected two designs after live security
##! review: (1) gating the count on connection_established/
##! connection_rejected instead of new_connection - doesn't defend against
##! spoofing at this deployment's host-based capture vantage point
##! (zeek-host-capture.service watches the monitored host's OWN interface,
##! so that host's real reply to a spoofed SYN is exactly as visible as a
##! reply to a genuine one), and drops real recall for filtered-host and
##! non-SYN scans; (2) a global per-window notice-volume cap - bounds the
##! metric-gaming impact but introduces a cheap, silent denial-of-detection
##! primitive (a burst of spoofed sources exhausts the cap, then a real
##! concurrent scan goes unnoticed with no telemetry marking the loss).
##! This script is UNCHANGED as a result - #331's actual fix is a
##! distinct-source cardinality signal in
##! scripts/setup/ai_agent/slo_metrics.py's metric_raw_alert_volume(). Do
##! not re-attempt either rejected design without re-reading that history.

@load base/frameworks/notice

module Scan;

export {
    redef enum Notice::Type += {
        ## A single source probed many distinct ports in a short window.
        Port_Scan,
    };

    ## Distinct destination ports from one source that trips the notice.
    option port_scan_threshold: count = 20;

    ## Sliding window over which distinct ports are counted per source.
    option port_scan_interval: interval = 5 min;

    ## Minimum gap between repeat notices for the same source. Short enough that
    ## re-running the validation suite re-fires, long enough that a single nmap
    ## sweep (which finishes in seconds) yields exactly one notice.
    option port_scan_resuppress: interval = 1 min;
}

# Distinct destination ports seen per source, expiring on inactivity.
global ports_per_src: table[addr] of set[port]
    &create_expire = port_scan_interval;

# Sources alerted on recently, so a single sweep emits one notice, not one per
# port — but the suppression lifts after port_scan_resuppress so re-tests fire.
global already_flagged: set[addr] &create_expire = port_scan_resuppress;

# new_connection fires on the initial SYN, so every probed port is counted
# regardless of whether the port is open, closed, or filtered.
event new_connection(c: connection)
    {
    local src = c$id$orig_h;

    if ( src in already_flagged )
        return;

    if ( src !in ports_per_src )
        ports_per_src[src] = set();

    add ports_per_src[src][c$id$resp_p];

    if ( |ports_per_src[src]| >= port_scan_threshold )
        {
        add already_flagged[src];
        # Reset the port set so the next sweep is counted as a fresh episode
        # once suppression lifts, rather than re-firing on a single connection.
        delete ports_per_src[src];
        # Suppress at the Notice framework for exactly port_scan_resuppress, not
        # the framework default (1 h). Without $suppress_for the default wins and
        # silently overrides the 1-min re-fire this script documents — so a single
        # source can never re-trigger within an hour, breaking re-validation and
        # leaving notice.log a single static line.
        NOTICE([$note = Scan::Port_Scan,
                $conn = c,
                $src = src,
                $msg = fmt("%s probed %d+ distinct ports", src, port_scan_threshold),
                $identifier = cat(src),
                $suppress_for = port_scan_resuppress]);
        }
    }
