# Suricata university starter set — landing record (#446, M23 Stage 3)

Companion to `docs/detections/suricata-ci-lane.md` (the CI lane itself,
#445). This doc records exactly what changed when the 100-rule
`university_soc_starter_ruleset.rules` source (supplied by the repo owner
2026-08-30) landed as `rules/suricata/*.rules`, and why.

## What landed

10 category files, SIDs 9000001-9000100, split exactly along the source's
own 10 category headers:

| File | SIDs | Category |
|---|---|---|
| `auth_sso_abuse.rules` | 9000001-9000010 | Authentication & SSO abuse |
| `phishing_email.rules` | 9000011-9000020 | Phishing & malicious email indicators |
| `web_lms_attacks.rules` | 9000021-9000030 | Web application attacks against LMS/portals |
| `web_shell_compromise.rules` | 9000031-9000040 | Web shell & server compromise |
| `ransomware_c2.rules` | 9000041-9000050 | Ransomware & malware C2 indicators |
| `residential_policy_violations.rules` | 9000051-9000060 | Residential network / policy violations |
| `exfiltration_dlp.rules` | 9000061-9000070 | Data exfiltration & DLP |
| `remote_access_abuse.rules` | 9000071-9000080 | Remote access abuse (RDP/VNC/SSH) |
| `recon_scanning.rules` | 9000081-9000090 | Reconnaissance & scanning |
| `iot_lab_research.rules` | 9000091-9000100 | IoT / lab & research network abuse |

Verified byte-for-byte against the source before anything else: every one
of the source's 100 `alert`-prefixed lines appears in exactly one category
file (stripped of the disabling `#`), with no line dropped, duplicated, or
altered in content beyond the syntax fixes below.

**Every rule shipped disabled** (leading `#`) per #446's own decision —
none had a pcap fixture, so none could enter the enabled set under #445's
promotion gate. `configs/suricata/suricata.yaml`'s `rule-files:` list
references all 10 files (plus `local.rules`).

**Update (2026-09-01, #446 follow-up):** 11 of the 100 rules are now
enabled — see "First 11 rules promoted" below. The other 89 remain
disabled for the reasons already documented in this file (unresolved
placeholders, un-tuned `detection_filter` thresholds, no fixture yet, or
DLP sign-off not obtained).

## Syntax fixes (8 rules)

Landing this set through the real #445 CI lane (`suricata -T` against
every rule's *uncommented* text — see `suricata_rules_eval.
check_syntax_including_disabled`, added specifically because Suricata's
loader silently ignores `#`-commented lines and would otherwise never
validate a disabled rule's syntax at all) surfaced 8 rules that do not
parse under the installed Suricata 7.0.3. Each is a mechanical
keyword/buffer compatibility fix, verified by hand with a real `suricata
-T` run before landing — no detection logic, message, classtype, SID, or
threshold value was invented or altered beyond what the fix required:

| SID | Problem | Fix |
|---|---|---|
| 9000003 | `dsize:>8000` combined with `http.uri` — dsize is a single-packet check, incompatible with app-layer/stream matching | `http.request_body; bsize:>8000` (same ">8000 byte body" intent) |
| 9000058, 9000063, 9000064, 9000069 | `http.hostname` is not a real Suricata 7.0.3 keyword | `http.host` (the real sticky buffer, already lowercase-normalized — redundant `nocase` dropped) |
| 9000062 | Bare `dns.query;` selector with no content/pcre match attached — Suricata rejects a sticky buffer with nothing matching it | Selector removed; the rule's actual intent (count every DNS query per source, threshold on volume) needs no query-content match — the protocol/port header already scopes it |
| 9000063, 9000064 | `dsize:>1000000` — same single-packet-vs-app-layer problem as 9000003, compounded by exceeding dsize's valid range (no single packet can be 1MB) | Same `http.request_body; bsize:>1000000` fix as 9000003 |
| 9000067 | `ftp.command` is not a real Suricata 7.0.3 keyword | `ftpdata_command:stor` — the real keyword for "which command opened this data channel"; requires the rule's protocol to be `ftp-data` (the data-channel flow), not `ftp` (control channel) — header changed accordingly |
| 9000072 | `rdp.cookie` is not a real Suricata 7.0.3 keyword — RDP is a recognized app-layer protocol in this build but no cookie-matching buffer is exposed | Dropped to a plain `tcp` rule matching the literal `Cookie: mstshash=` field — the MS-RDPBCGP X.224 Connection Request carries its routing cookie as cleartext ASCII before encryption negotiates; a well-documented, publicly known RDP-scanner fingerprint, not a new indicator |

Each fix is also commented inline, in place, in the affected `.rules`
file. `tests/detections/test_suricata_rules.py`'s
`SyntaxGateRealRepoTests.test_suricata_dash_t_validates_every_rule_even_
disabled` now passes against the real, landed set — all 100 rules parse
as valid Suricata 7.0.3 syntax, disabled or not.

## Unresolved placeholders — left exactly as supplied

Per this repo's own conventions (never invent an IOC, domain, or
credential), the following are **not** resolved and must not be enabled
until a human with real institutional/threat-intel context does so:

- **9000013** (`phishing_email.rules`) — `univv-edu` is the source's own
  illustrative look-alike-domain string. Suburban-SOC is a residential
  mesh network, not a university, so there is no real institutional
  domain to substitute.
- **9000065** (`exfiltration_dlp.rules`) — `STU\d{7}` is the source's own
  illustrative student-ID format ("Adjust to Real Format" per its own
  msg), not a verified real ID format for any institution.
- **9000099** (`iot_lab_research.rules`) — `iotbotnet` is the source's
  own illustrative placeholder C2 domain fragment ("Replace with Real
  Threat Intel" per its own msg), not a real, sourced indicator.

## DLP sign-off — not obtained this session

**9000065** and **9000066** (`exfiltration_dlp.rules`) match regulated
data (FERPA student IDs, PCI payment-card PANs) in outbound traffic. Per
#446's own instruction, these must not be bulk-enabled with the rest of
the set even once fixtures exist — they need explicit, documented
sign-off from whoever owns data-handling policy for this deployment. Not
obtained here; flagged inline in the rule file and in
`coverage_checklist.md`.

## Reconciliation against existing Sigma coverage

The source ruleset claimed 8 overlapping pairs with this repo's existing
`rules/sigma/` coverage; the prior session (2026-08-30, M23 Stage 1)
cross-checked all 8 and found one correction. This session re-verified
every claim directly against the real Sigma rule files before writing it
down here, and found one additional overlap the source's own list didn't
mention:

| Suricata SID(s) | Sigma rule | Verified how |
|---|---|---|
| 9000041 (DGA/high-entropy DNS) | `net_zeek_dns_dga_nxdomain_burst.yml`, `net_zeek_dns_tunneling_high_entropy.yml` | Both use the same 20-40+ char run-length shape on `dns.query` |
| 9000050 (Cobalt Strike malleable URI) | `net_zeek_http_cobalt_strike_beacon.yml` | `/jquery-3.3.1.min.js` is literally one of that rule's 6 listed URIs |
| 9000053 (Tor OR/directory port) | `net_zeek_conn_tor_exit_node.yml` | Same ports (9001/9030) |
| 9000057 (cryptomining pool DNS) | `net_zeek_dns_crypto_mining_pool.yml` | Same detection modality (DNS query to known pool domain) |
| 9000061 (long DNS query) | `net_zeek_dns_tunneling_high_entropy.yml` | Same signal (query length), different threshold (60+ vs. 50+ chars) |
| 9000063, 9000064 (large POST to mega.nz/dropbox) | `net_zeek_ssl_cloud_storage_exfil.yml` | Both hostnames confirmed literally on that rule's SNI provider list |
| **9000069** (pastebin.com paste site) | `net_zeek_ssl_cloud_storage_exfil.yml` | `pastebin.com` is ALSO on that same provider list — **not called out by the source's own claimed-overlap list**, found independently while verifying it |
| 9000071 (inbound RDP) | `net_zeek_conn_external_rdp_inbound.yml` | Same port (3389), same "not-internal-source" logic |
| 9000073 (repeated external SSH attempts) | `net_zeek_ssh_bruteforce.yml` | Different method (Suricata connection-count threshold vs. Zeek's own notice), same activity |
| 9000082 (high-volume SYN from one source) | `net_zeek_port_scan.yml` | Different method (Suricata SYN-flag counting vs. Zeek's own scan notice), same activity |

**9000077** (HOME_NET-initiated *outbound* RDP) has **no** existing Sigma
equivalent — the source's own claimed-overlap list bundles it with
9000071, but that overlap only actually holds for 9000071's *inbound*
direction (confirmed by the prior session, re-confirmed here). 9000077 is
a genuine new gap this set closes, not overlap.

**Decision for every overlapping pair: keep both as independent
confirmation, deferred.** Neither the Sigma rule nor the Suricata rule
auto-triggers SOAR containment today — Stage 1's Category 0b `eve.json`
ingest is dashboard-only by design (no live alert-quality data yet to
justify auto-triggering off an untuned source) — so there is no
double-trigger risk at this stage regardless of which way this is
decided. Suppress-vs-keep is a real tuning decision that needs live
alert-quality data from both sources side by side; making it now, with
zero rules even enabled yet, would be guessing. Revisit once both sides
have real traffic to compare.

## Genuine new coverage this set closes

No existing Sigma equivalent exists for: raw-IP TLS SNI (9000049),
BitTorrent handshake/DHT (9000051/9000052), DNS query-volume threshold
(9000062), HOME_NET-initiated outbound RDP (9000077), Mirai-style telnet
defaults (9000091/9000092), and IoT/ICS port exposure — MQTT, CoAP,
Modbus, S7comm (9000094-9000097). Confirmed by checking each SID's
signal shape against the full `rules/sigma/` corpus, not assumed from the
source's own claims.

## First 11 rules promoted (2026-09-01, #446 follow-up)

11 of the 100 rules had no placeholder to resolve and no `detection_filter`
threshold to tune — plain port/protocol or fixed-content matches, safe to
verify and enable without live traffic or a human sign-off decision. Each
got a real, verified pcap fixture (`suricata -r` replay against the actual
rule text, real Suricata 7.0.3 + real `scapy`-built packets — same
verification posture as #445's own promotion-gate tests, not a hand-authored
pcap taken on faith) and was flipped from `#alert` to `alert`:

| SID | Rule | Fixture shape |
|---|---|---|
| 9000049 | TLS SNI is a raw IP address (`ransomware_c2.rules`) | Real `scapy` TLS 1.2 ClientHello with an SNI extension carrying an IP-literal string (TP) vs. a hostname (TN), over a full TCP 3-way handshake |
| 9000051 | BitTorrent handshake (`residential_policy_violations.rules`) | TCP payload starting `\x13BitTorrent protocol` (TP) vs. a plain HTTP GET on the same port (TN) |
| 9000052 | BitTorrent DHT (`residential_policy_violations.rules`) | UDP payload starting `d1:ad2:id20:` (TP) vs. benign UDP payload (TN) |
| 9000091 | Mirai telnet default root/xc3511 (`iot_lab_research.rules`) | TCP:23 payload `root\r\nxc3511` (TP) vs. a different login pair (TN) |
| 9000092 | Mirai telnet default admin/admin (`iot_lab_research.rules`) | Same shape, `admin\r\nadmin` |
| 9000093 | Outbound telnet from HOME_NET (`iot_lab_research.rules`) | Any established TCP flow to EXTERNAL_NET:23 (TP) vs. the same flow to :443 (TN) — no content match in the rule itself |
| 9000094 | CoAP port exposure (`iot_lab_research.rules`) | UDP to HOME_NET:5683 (TP) vs. :53 (TN) |
| 9000095 | MQTT port exposure (`iot_lab_research.rules`) | Established TCP to HOME_NET:1883 (TP) vs. :8080 (TN) |
| 9000096 | Modbus port exposure (`iot_lab_research.rules`) | Established TCP to HOME_NET:502 (TP) vs. :5020 (TN) |
| 9000097 | S7comm port exposure (`iot_lab_research.rules`) | Established TCP to HOME_NET:102 (TP) vs. :1020 (TN) |
| 9000098 | Default admin:admin Basic Auth (`iot_lab_research.rules`) | HTTP request carrying `Authorization: Basic YWRtaW46YWRtaW4=` (TP) vs. a Bearer token (TN) |

Fixtures live at `tests/detections/fixtures/suricata/<SID>_tp.pcap` /
`<SID>_tn.pcap`. `tests/detections/test_suricata_rules.py`'s
`PromotionGateRealRepoTests` now covers all 11 as part of the real,
enabled-rule set (not just the synthetic meta-tests #445 originally
proved the mechanism with).

**Deliberately excluded from this batch even though they're also
placeholder/threshold-free:** none — every other rule in the 100 has
either an unresolved placeholder, a `detection_filter` threshold, is one
of the two DLP rules needing sign-off, or (the large majority) is a
straightforward content/port match like the 11 above but simply wasn't
reached this session — building and hand-verifying a fixture per rule is
real, one-at-a-time work; the remaining ~89 need the same treatment, not
a different decision.

## What is still NOT done

- **89 rules still have no pcap fixture** and stay disabled; #445's
  promotion gate needs one per rule before any more can be enabled — the
  same real, one-at-a-time verification work the 11 above just went
  through, not yet done for the rest.
- **3 unresolved placeholders** (9000013, 9000065, 9000099, see above) —
  still blocked on a human with real institutional/threat-intel context;
  not attempted.
- **No threshold tuning.** Every remaining `detection_filter`
  count/seconds value is the source's own illustrative default, disclosed
  as such inline — not validated against this deployment's actual
  traffic (no live traffic exists in this sandbox to tune against).
- **DLP sign-off** (9000065/9000066) — still not obtained.
- **ATT&CK coverage** — still explicitly scoped out
  (`findings/20260830-445-suricata-attack-coverage-scope.md`); this
  landing doesn't change that decision, it's the trigger to eventually
  revisit it.
