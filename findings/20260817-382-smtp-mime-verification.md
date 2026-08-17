# #382 — SMTP `mime_type` live verification

Live-fire verification of `net_zeek_smtp_attachment_executable.yml`'s runtime
assumptions, none of which had been independently confirmed against a genuine
plaintext SMTP session before this — only reasoned about from source code and
from #365's HTTP-only testing.

## Methodology

A minimal raw-socket SMTP client/server (not committed — throwaway, lives in
this session's scratchpad) exchanged four plaintext SMTP sessions, each
carrying one MIME attachment. All four client/server/tcpdump processes ran
inside a single container sharing one network namespace (`docker run --net=host
--cap-add=NET_RAW --cap-add=NET_ADMIN`) — a first attempt splitting tcpdump
into a separate container captured 0 packets, because this environment's shell
network namespace is isolated from a separate `--net=host` container's
namespace. The resulting pcap was replayed through the same pinned
`zeek/zeek:8.2.1@sha256:eca2b3915d3e067cbb4a904f23f4c4f461ea2b60613ab30f7ee77bbc707c87c7`
image #365 used, reading `files.log` back.

- **Attachment binary:** `notepad.exe`, pulled from this WSL host's own
  mounted `C:\Windows` — a real, genuine compiler-output PE binary, matching
  #365's own precedent for authenticity (not a hand-crafted header).
  SHA-256: `3f543719a819a9769d8f138a02544f93af8b53ef1779a96bc2403715d9a55380`
- **Capture pcap SHA-256:**
  `02c5e0030fc9010fca5ce1d3c563340482c687b5818ea4c1bd201a351f9cc1bf`
- All four messages declared `Content-Type: application/x-msdownload` in the
  MIME part headers, matching a real mailer's typical declared header for a
  `.exe` attachment.

## Scenarios and results

| # | Attachment bytes | Content-Transfer-Encoding | `mime_type` | `analyzers` | `seen_bytes` |
|---|---|---|---|---|---|
| a | Full `notepad.exe` (360448 bytes) | base64 | `application/x-dosexec` | `["PE"]` | 360448 |
| b | First 16 bytes of `notepad.exe` | base64 | `application/x-dosexec` | `["PE"]` | 16 |
| c | 200 zero-bytes (no MZ/PE signature) | base64 | *(field absent)* | `[]` | 200 |
| d | First 4096 bytes of `notepad.exe` | quoted-printable | `application/x-dosexec` | `["PE"]` | 4110 |

Every record also carried `source: "SMTP"` and (where content-magic
succeeded) `filename: "notepad.exe"` — the declared MIME filename, which is
attacker-controlled, not content-derived.

Raw `files.log` (JSON, one record per line, 2 records per scenario — the
`text/plain` records are the MIME preamble's plain-text body part, not the
attachment):

```json
{"ts":1787009944.863145,"fuid":"FO11hn4e7Dnfy43xo","uid":"CTFBJR8UrvmvlvBb8","id.orig_h":"127.0.0.1","id.orig_p":54640,"id.resp_h":"127.0.0.1","id.resp_p":2525,"source":"SMTP","depth":2,"analyzers":[],"mime_type":"text/plain","duration":0.0,"local_orig":true,"is_orig":true,"seen_bytes":13,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787009944.863145,"fuid":"FlrVR11QZpCRHfXzua","uid":"CTFBJR8UrvmvlvBb8","id.orig_h":"127.0.0.1","id.orig_p":54640,"id.resp_h":"127.0.0.1","id.resp_p":2525,"source":"SMTP","depth":3,"analyzers":["PE"],"mime_type":"application/x-dosexec","filename":"notepad.exe","duration":0.00146484375,"local_orig":true,"is_orig":true,"seen_bytes":360448,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787009945.441416,"fuid":"FH75ie35XNRfJlykti","uid":"C9anhK3ZEBq1zhuOY2","id.orig_h":"127.0.0.1","id.orig_p":54650,"id.resp_h":"127.0.0.1","id.resp_p":2525,"source":"SMTP","depth":2,"analyzers":[],"mime_type":"text/plain","duration":0.0,"local_orig":true,"is_orig":true,"seen_bytes":13,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787009945.441416,"fuid":"Fvu63Z10YdGg1Y8FQh","uid":"C9anhK3ZEBq1zhuOY2","id.orig_h":"127.0.0.1","id.orig_p":54650,"id.resp_h":"127.0.0.1","id.resp_p":2525,"source":"SMTP","depth":3,"analyzers":["PE"],"mime_type":"application/x-dosexec","filename":"notepad.exe","duration":0.0,"local_orig":true,"is_orig":true,"seen_bytes":16,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787009946.002642,"fuid":"FYcSys1etD6w7uQIAi","uid":"CZ0CdL1arlCU8PwcJb","id.orig_h":"127.0.0.1","id.orig_p":54660,"id.resp_h":"127.0.0.1","id.resp_p":2525,"source":"SMTP","depth":2,"analyzers":[],"mime_type":"text/plain","duration":0.0,"local_orig":true,"is_orig":true,"seen_bytes":13,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787009946.002642,"fuid":"F4TvV62AQmLJ3zgZ3k","uid":"CZ0CdL1arlCU8PwcJb","id.orig_h":"127.0.0.1","id.orig_p":54660,"id.resp_h":"127.0.0.1","id.resp_p":2525,"source":"SMTP","depth":3,"analyzers":[],"filename":"notepad.exe","duration":0.0,"local_orig":true,"is_orig":true,"seen_bytes":200,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787009946.564319,"fuid":"FeDuty3vgvJxBBFgvd","uid":"CmNAVd4MX872gN0PPl","id.orig_h":"127.0.0.1","id.orig_p":54672,"id.resp_h":"127.0.0.1","id.resp_p":2525,"source":"SMTP","depth":2,"analyzers":[],"mime_type":"text/plain","duration":0.0,"local_orig":true,"is_orig":true,"seen_bytes":13,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787009946.564319,"fuid":"F1UOlB41AxR9NbVPI1","uid":"CmNAVd4MX872gN0PPl","id.orig_h":"127.0.0.1","id.orig_p":54672,"id.resp_h":"127.0.0.1","id.resp_p":2525,"source":"SMTP","depth":3,"analyzers":["PE"],"mime_type":"application/x-dosexec","filename":"notepad.exe","duration":0.0,"local_orig":true,"is_orig":true,"seen_bytes":4110,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
```

## Conclusions

1. `source: "SMTP"` confirmed at runtime (settles the
   `base/protocols/smtp/entities.zeek` source-code assertion the rule's
   description already made, with an actual observation).
2. Content-magic detection is transport-agnostic in practice, not just by
   design: the same binary produces the identical `application/x-dosexec`
   over SMTP that #365 already found over HTTP.
3. Quoted-printable-encoded attachments are correctly decoded by Zeek's SMTP
   MIME entity parser before content-magic runs — not a bypass vector, at
   least for this one alternate encoding.
4. Content-magic does NOT fall back to a mail entity's declared
   `Content-Type` header when file bytes are inconclusive — confirmed for
   exactly one all-zero-byte case (scenario c). This is evidence, not proof,
   for the general claim; ambiguous-but-nonzero byte patterns, other
   transfer encodings (uuencode, yEnc, a declared-but-wrong CTE), and a
   payload that content-magic types as some OTHER wrong-but-conclusive
   type were not tested.
5. **A real, disclosed gap, not just a settled question:** scenario (c)'s
   `mime_type`-absent record is itself an evasion primitive — a file that
   Zeek's narrow signature set can't type produces no `mime_type` at all,
   and this rule's equality selection can never fire against a missing
   field. Archive/packed/container/script-interpreter payload classes
   (#384, already filed) are the realistic instances of this, not a
   theoretical edge case.

Full reasoning and citations: parallel security-auditor + code-reviewer
review on the PR that closed #382 (`rules/sigma/net_zeek_smtp_attachment_executable.yml`'s
`description:` block carries the operator-facing summary of all of the
above).
