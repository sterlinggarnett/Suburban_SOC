# M23 Detections CI — live-fire failure triage (2026-09-02)

## Scope
"Detections CI" workflow (`.github/workflows/detections.yml`), non-required `live-fire`
job. Reviewed all recent failing runs on branch `claude/backlog-work-session-ywjz3t`
(runs 33543625017 … 33643287557) plus the green runs on the same commits.

## Finding: exactly one live-fire failure, and it is flaky, not a real regression
- **Failing test:** `tests/detections/test_zeek_mime_detection.py::ZeekMimeDetectionLiveFireTests::test_smtp_attachment_types_as_text_x_shellscript_and_tags_source_smtp`
- **Symptom:** `AssertionError: [] is not true … no files.log record typed 'text/x-shellscript' with source=SMTP`. Zeek produced only `conn.log` + `packet_filter.log`, no `smtp.log`/`files.log`.
- **Flaky:** same branch/commit passed in run 33644149940 and failed in 33643287557 (+6 others).
- **Elasticsearch live-fire step (`test_live_fire.py`) passes in CI in every run** — it is NOT a CI failure. (A local run against the live TLS production stack shows one threshold subfailure for `disc-win-nltest-discovery-repeat.ndjson`; that is a local-stack index-template mapping artifact — the clean ephemeral CI ES container maps the aggregation field as keyword by default and passes. Out of scope.)

## Root cause (confirmed empirically, not inferred)
The test captures a real loopback SMTP exchange with `tcpdump -w`, then replays the pcap
through the pinned `zeek/zeek:8.2.1` image. The capture was truncated:

- The full 24-packet exchange always reached the wire — `sendmail()` completed with a full
  SMTP transcript (EHLO→MAIL FROM→DATA→base64 attachment→QUIT), and tcpdump's own counters
  reported `received by filter = 48`, `dropped by kernel = 0`.
- But `packets captured` (what tcpdump actually wrote) was nondeterministically truncated to
  0 / 8 / 24. At 8 packets the pcap holds only handshake + SMTP banner + EHLO, so Zeek never
  attaches the SMTP analyzer and never extracts the MIME file → empty `files.log`.
- Mechanism: tcpdump's default TPACKET_V3 ring hands packets to userspace in **timer-retired
  blocks**, so a sub-100ms exchange's packets dribble into the save file in bursts over ~1s+
  *after* the exchange finished. The old `_Capture.stop()` did a fixed `time.sleep(0.5)` then
  SIGTERM, terminating tcpdump before the ring drained. SIGTERM does not drain the ring.

Reproduced 0/10 with the original code; a pre-exchange timing sweep showed the same input
yielding 0, 8, or 24 captured packets with `dropped=0` throughout.

## Fix (tests/detections/test_zeek_mime_detection.py, `_Capture`)
1. `__init__`: add `--immediate-mode` to tcpdump — deliver each packet as captured, bypassing
   the ring's block-retirement timer so the save file tracks the wire in real time.
2. `stop()`: replace the fixed 0.5s sleep with a condition-based poll — wait until the pcap
   size grows past the 24-byte header and then holds steady for 0.6s (15s deadline) before
   terminating tcpdump.

## Validation
- End-to-end harness (real `_Capture` → pinned Zeek replay): 6/6 runs captured 24 packets and
  Zeek emitted the `text/x-shellscript` + `source=SMTP` files.log record.
- Real `pytest tests/detections/test_zeek_mime_detection.py`: **5/5 pass** (HTTP + SMTP), was
  **0/5** before the fix. `ruff check` clean.
- Environment: Python 3.11 container (repo pins requires-python <3.12; smtpd removed in 3.12),
  host Docker daemon, host-shared TMPDIR so nested `docker run -v` bind-mounts resolve.
