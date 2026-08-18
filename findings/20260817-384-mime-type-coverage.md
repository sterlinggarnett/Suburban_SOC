# #384 — mime_type coverage expansion, live verification

Live-fire verification of every "unconfirmed" `mime_type` string #384 asked
about for `net_zeek_executable_download.yml`/`net_zeek_smtp_attachment_
executable.yml`, plus source-level cross-checks against Zeek's own signature
definitions (not pcap-replay alone).

## Methodology

13 real payloads served over real plaintext HTTP (Python's `http.server`),
captured to a real pcap via `tcpdump` (all three processes — capture,
server, client — run inside one container sharing a network namespace,
matching the lesson from #382/#383: a separate `--net=host` container
captures 0 packets from this sandbox's own shell namespace), replayed
through the same pinned
`zeek/zeek:8.2.1@sha256:eca2b3915d3e067cbb4a904f23f4c4f461ea2b60613ab30f7ee77bbc707c87c7`
image #365 used. Every result was then independently cross-checked by
reading Zeek's own signature source
(`/usr/local/zeek/share/zeek/base/frameworks/files/magic/*.sig` inside the
image) — not trusting the pcap-replay result alone.

Payload construction favored real tools over hand-crafted bytes wherever a
real tool exists (matching #365's own precedent, which replaced a hand-
crafted PE test with genuine compiler output after review questioned its
representativeness):

- **Real tool output**: `.iso` via `genisoimage` (Debian package), `.msi`
  via `msitools`' `msibuild` (genuine OLE Compound File Binary Format), the
  Mach-O object via `clang -target x86_64-apple-macos11 -c` (genuine
  compiler output, Debian's clang package — cross-compiles without a macOS
  SDK; produces a relocatable `.o`, not a linked executable, but Zeek's own
  signature is confirmed filetype-agnostic, see below).
- **Spec-accurate hand-built**: `.lnk` — no Linux tool exists for this, so
  built directly from the MS-SHLLINK 2.1 specification (a 76-byte
  `ShellLinkHeader`, fixed `HeaderSize`/`LinkCLSID`/no optional structures)
  using Python's `uuid` module for correct mixed-endian GUID encoding — not
  an arbitrary byte blob. Confirmed byte-for-byte against Zeek's own LNK
  signature after the fact (see below).
- **Plain text**: Python/Perl/Ruby/`.ps1`/`.bat`/`.vbs`/`.js`/`.wsf`/`.hta`
  droppers — realistic file content, no interpreter needed since Zeek only
  inspects bytes, never executes anything.

SHA-256 hashes (payloads + pcap):

```
df4d54a955fd50cb1e69619e72313ae9ddd4dd2191c3bdf2073a85beff9d70c0  mime384.pcap
125f42e49a2df23fb2d3fc2569e355d9ac97f8e5f12dc5e3efdc5f234c6ba276  dropper.bat
b617f3c0c7e551cc8af49f0e4831a66fdcd4b50257dbfba12efbb9db720e1e8d  dropper.hta
ae0f66628fde4bbb851e555874da7194770ec97c5a20fc14316202e7c444bb52  dropper.iso
3d962363b95acb576063c422a9285d28d8d7ba0c1b193b137f2b40f076af6504  dropper.js
80a2849d04ce101a9f6df02423dc4f9e4b4f0744650adaec2f146b1896f99369  dropper.lnk
4f0d32409cf0264f1db889c7d2aa74f1bfaece05c75f6a5766d445fbb3b010dd  dropper.msi
205a8031211b5c9ad093e70c39f0bae756e439120212a79e9ef71043c3d286b2  dropper.pl
f54bca8311a32d5928e27ba566add0415706e56a4c35188b2b529471e600fd7c  dropper.ps1
59e88aaf6688f8101f1b1675f26a77ee60de439779db5cde4dd22a088850266a  dropper.py
f156205efc4c51d3db57863b60e758cee7129a8ca5e9154cd41fcefd281abbb2  dropper.rb
d626f424342a1d7608989ff50711eb8b9262ac21a0ff6cb5dc52a7e4dfed05bb  dropper.vbs
f9bedd613f07403761017ce5861d9aa9b788aa502ea24cfd5238727b0f205b53  dropper.wsf
deac66ccb79f6d31c0fa7d358de48e083c15c02ff50ec1ebd4b64314b9e6e196  hello.c   (source for the Mach-O build)
09593f726352e623f925a3dc0b55654e92620461e7ea4440745b990fe10c9337  hello.o   (Mach-O object)
```

## Results

| Payload | Confirmed `mime_type` (live) | Confirmed via signature source | Added to rules? |
|---|---|---|---|
| `dropper.py` (`#!/usr/bin/env python3`) | `text/x-python` | `file-python`: `^#![^\n]{1,15}bin/(env )?python`, priority 60 | **Yes** |
| `dropper.pl` (`#!/usr/bin/perl`) | `text/x-perl` | `file-perl`: same shape, `perl` | **Yes** |
| `dropper.rb` (`#!/usr/bin/env ruby`) | `text/x-ruby` | `file-ruby`: same shape, `ruby` | **Yes** |
| `dropper.bat` (`@echo off`...) | `text/x-msdos-batch` | `file-batch1/2/3`: content must START with `@echo off` / `@rem` / `@set ` (case-insensitive) — narrower than "any .bat file" | **Yes** |
| `dropper.lnk` (spec-accurate header) | `application/x-ms-shortcut` | `file-lnk`: fixed 20-byte magic, byte-for-byte match to the built header | **Yes** |
| `hello.o` (real clang Mach-O object) | `application/x-mach-o-executable` | `file-mach-o`: `^[\xce\xcf]\xfa\xed\xfe` — confirmed **filetype-agnostic** (no check on the MH_OBJECT/MH_EXECUTE field), so this result is representative of a linked executable too | **Yes** |
| `dropper.ps1` | `text/plain` | no PowerShell-specific signature exists anywhere in the image | No — too broad, disclosed |
| `dropper.vbs` | `text/plain` | no VBScript-specific signature exists | No — too broad, disclosed |
| `dropper.js` | `text/plain` | no JScript-specific signature exists | No — too broad, disclosed |
| `dropper.wsf` | `text/plain` | no WSF-specific signature exists | No — too broad, disclosed |
| `dropper.hta` | `text/html` | matches the generic HTML signature (HTA is just HTML+script) | Already covered by an existing detection angle, not this rule's scope |
| `dropper.iso` (real genisoimage output, valid `CD001` at offset 32769) | *(absent — no match at all)* | confirmed via `grep -il "iso9660\|CD001"` across every `.sig` file in the image: **zero matches**, no ISO9660 signature exists | No — cannot be, absent field |
| `dropper.msi` (real msibuild/OLE output) | `application/msword` | `file-msword`: `^\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1` — Zeek's OWN comment: *"This signature is non-specific and terrible but after searching for a long time there doesn't seem to be a better option."* | No — would flag every legitimate Word doc; filed as [#417](https://github.com/voltron-1/Suburban_SOC/issues/417) |

Raw `files.log` (JSON, one record per fetched payload, in fetch order —
`bat, hta, iso, js, lnk, msi, pl, ps1, py, rb, vbs, wsf, hello.c, hello.o`):

```json
{"ts":1787011486.9437,"fuid":"FgG3Qo1UZotSBJAcIh","uid":"COf5Qp4qwkDGDFwev8","id.orig_h":"127.0.0.1","id.orig_p":33632,"id.resp_h":"127.0.0.1","id.resp_p":8384,"source":"HTTP","depth":0,"analyzers":[],"mime_type":"text/x-msdos-batch","duration":0.0,"local_orig":true,"is_orig":false,"seen_bytes":114,"total_bytes":114,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787011487.149544,"fuid":"F1GE0t1x4LzkthVGzh","uid":"ChhQLf1kwIpLrpHomf","id.orig_h":"127.0.0.1","id.orig_p":33640,"id.resp_h":"127.0.0.1","id.resp_p":8384,"source":"HTTP","depth":0,"analyzers":[],"mime_type":"text/html","duration":0.0,"local_orig":true,"is_orig":false,"seen_bytes":192,"total_bytes":192,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787011487.356289,"fuid":"FtZ2bI2CnZiB1xD74g","uid":"Cu6mnO1nP4vqQZBHse","id.orig_h":"127.0.0.1","id.orig_p":33652,"id.resp_h":"127.0.0.1","id.resp_p":8384,"source":"HTTP","depth":0,"analyzers":[],"duration":0.0002751350402832031,"local_orig":true,"is_orig":false,"seen_bytes":372736,"total_bytes":372736,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787011487.563269,"fuid":"FwFD583WkarDjgiXkb","uid":"C69kqDwAau1ihL0c2","id.orig_h":"127.0.0.1","id.orig_p":33666,"id.resp_h":"127.0.0.1","id.resp_p":8384,"source":"HTTP","depth":0,"analyzers":[],"mime_type":"text/plain","duration":0.0,"local_orig":true,"is_orig":false,"seen_bytes":89,"total_bytes":89,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787011487.771256,"fuid":"FZPVDd4Sdh4B6PxJmg","uid":"CwXMjN18c7QzTN2Lph","id.orig_h":"127.0.0.1","id.orig_p":33676,"id.resp_h":"127.0.0.1","id.resp_p":8384,"source":"HTTP","depth":0,"analyzers":[],"mime_type":"application/x-ms-shortcut","duration":0.0,"local_orig":true,"is_orig":false,"seen_bytes":76,"total_bytes":76,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787011487.981462,"fuid":"F1BXq42yfTs3chRcX5","uid":"CVCf2u2leNmNA81Vfc","id.orig_h":"127.0.0.1","id.orig_p":33692,"id.resp_h":"127.0.0.1","id.resp_p":8384,"source":"HTTP","depth":0,"analyzers":[],"mime_type":"application/msword","duration":0.0,"local_orig":true,"is_orig":false,"seen_bytes":3072,"total_bytes":3072,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787011488.192307,"fuid":"FWonDF4RDaVczqnsch","uid":"CS3j87ueVngF4oEdd","id.orig_h":"127.0.0.1","id.orig_p":33700,"id.resp_h":"127.0.0.1","id.resp_p":8384,"source":"HTTP","depth":0,"analyzers":[],"mime_type":"text/x-perl","duration":0.0,"local_orig":true,"is_orig":false,"seen_bytes":50,"total_bytes":50,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787011488.397335,"fuid":"FYLOBiHbGoyLSJQ21","uid":"Cer4i116hOjNKLrO92","id.orig_h":"127.0.0.1","id.orig_p":33712,"id.resp_h":"127.0.0.1","id.resp_p":8384,"source":"HTTP","depth":0,"analyzers":[],"mime_type":"text/plain","duration":0.0,"local_orig":true,"is_orig":false,"seen_bytes":152,"total_bytes":152,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787011488.603906,"fuid":"FNpKiX3SyrrNoQVlM5","uid":"Ch3It9I9sTrzpDX3l","id.orig_h":"127.0.0.1","id.orig_p":33716,"id.resp_h":"127.0.0.1","id.resp_p":8384,"source":"HTTP","depth":0,"analyzers":[],"mime_type":"text/x-python","duration":0.0,"local_orig":true,"is_orig":false,"seen_bytes":88,"total_bytes":88,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787011488.809832,"fuid":"FL0R6y1hJxV16BWHU2","uid":"CjrAZf4qzLpDuCVP9i","id.orig_h":"127.0.0.1","id.orig_p":33720,"id.resp_h":"127.0.0.1","id.resp_p":8384,"source":"HTTP","depth":0,"analyzers":[],"mime_type":"text/x-ruby","duration":0.0,"local_orig":true,"is_orig":false,"seen_bytes":49,"total_bytes":49,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787011489.018801,"fuid":"FC6iWl222DTY2fu6yc","uid":"C073tl4canGgJYY816","id.orig_h":"127.0.0.1","id.orig_p":33734,"id.resp_h":"127.0.0.1","id.resp_p":8384,"source":"HTTP","depth":0,"analyzers":[],"mime_type":"text/plain","duration":0.0,"local_orig":true,"is_orig":false,"seen_bytes":88,"total_bytes":88,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787011489.226121,"fuid":"FqyNkt2e8TnGSAftxh","uid":"CVoUpM1CK25kv7eCl2","id.orig_h":"127.0.0.1","id.orig_p":33746,"id.resp_h":"127.0.0.1","id.resp_p":8384,"source":"HTTP","depth":0,"analyzers":[],"mime_type":"text/plain","duration":0.0,"local_orig":true,"is_orig":false,"seen_bytes":150,"total_bytes":150,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787011489.433198,"fuid":"Fm3pKN2u4ZXBxQwUze","uid":"C9YhEi4s8nvy3tThj7","id.orig_h":"127.0.0.1","id.orig_p":33754,"id.resp_h":"127.0.0.1","id.resp_p":8384,"source":"HTTP","depth":0,"analyzers":[],"mime_type":"text/plain","duration":0.0,"local_orig":true,"is_orig":false,"seen_bytes":25,"total_bytes":25,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
{"ts":1787011489.639291,"fuid":"FId46j3mxITM1orpzh","uid":"CDJyWm1KykzDc9RSO8","id.orig_h":"127.0.0.1","id.orig_p":33770,"id.resp_h":"127.0.0.1","id.resp_p":8384,"source":"HTTP","depth":0,"analyzers":[],"mime_type":"application/x-mach-o-executable","duration":0.0,"local_orig":true,"is_orig":false,"seen_bytes":616,"total_bytes":616,"missing_bytes":0,"overflow_bytes":0,"timedout":false}
```

## Post-review verification

Parallel security-auditor + code-reviewer review found the first draft's
evidence chain had real gaps. Both closed with additional live-fire work,
not just wording fixes:

**Signature source attribution** (security-auditor: quotes were paraphrased
without file paths, not independently reproducible). Verbatim
`grep -i -B3 -A3` transcripts, by file:

`base/frameworks/files/magic/programming.sig`:
```
signature file-perl {
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?perl/
	file-mime "text/x-perl", 60
}
signature file-ruby {
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?ruby/
	file-mime "text/x-ruby", 60
}
signature file-python {
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?python/
	file-mime "text/x-python", 60
}
signature file-batch1 {
	file-mime "text/x-msdos-batch", 110
	file-magic /\x40 *[eE][cC][hH][oO] {1,}[oO][fF][fF]/
}
signature file-batch2 {
	file-mime "text/x-msdos-batch", 60
	file-magic /\x40[rR][eE][mM]/
}
signature file-batch3 {
	file-mime "text/x-msdos-batch", 70
	file-magic /\x40[sS][eE][tT] {1,}/
}
```

`base/frameworks/files/magic/general.sig`:
```
# Microsoft LNK files
signature file-lnk {
	file-mime "application/x-ms-shortcut", 49
	file-magic /^\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46/
}
```

`base/frameworks/files/magic/office.sig`:
```
# This signature is non-specific and terrible but after
# searching for a long time there doesn't seem to be a
# better option.
signature file-msword {
	file-magic /^\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1/
	file-mime "application/msword", 50
}
```

`base/frameworks/files/magic/executable.sig`:
```
# Mac OS X Mach-O executable
signature file-mach-o {
	file-magic /^[\xce\xcf]\xfa\xed\xfe/
	file-mime "application/x-mach-o-executable", 100
}
# Mac OS X Universal Mach-O executable
signature file-mach-o-universal {
	file-magic /^\xca\xfe\xba\xbe..\x00[\x01-\x14]/
	file-mime "application/x-mach-o-executable", 100
}
```

Confirmed via `grep -il "iso9660\|CD001"` across every `.sig` file in the
image: zero matches anywhere — the ISO9660 absent-`mime_type` result has no
competing explanation.

**Mach-O fat/universal binaries** (security-auditor, HIGH): the original
test only covered a thin binary. Fat/universal (`CA FE BA BE` magic) is the
dominant modern macOS distribution form post-Apple-Silicon and has a
genuinely separate signature (`file-mach-o-universal` above) that the thin
signature's magic bytes cannot match. Built a REAL universal binary to
close this rather than just disclose it: `clang -target arm64-apple-macos11
-c` and `clang -target x86_64-apple-macos11 -c` against the same `hello.c`,
combined with `llvm-lipo -create ... -output dropper_universal.o`
(Debian's `llvm` package ships `llvm-lipo-14` at
`/usr/lib/llvm-14/bin/llvm-lipo`, not on `PATH` by its bare name). Result:
`CA FE BA BE 00 00 00 02...` (2 architectures), 16912 bytes, SHA-256
`6e966ff8af925cf0b2837c7adee07ecac7582a803c1a1d748ce7f000ddb4a5ab`.
Live-fire tested the same way as the other 13 payloads: served over
plaintext HTTP, captured, replayed through the pinned image —
`mime_type: "application/x-mach-o-executable"`, identical to the thin
result. One mime_type entry genuinely covers both cases; no rule change
needed beyond what was already shipped, only the disclosure needed
completing.

**Perl/Ruby against real Elasticsearch** (security-auditor, LOW: only 4 of
6 new values were spot-checked against real ES with the real compiled
query in the original pass — perl and ruby were verified via
`sigma_eval.py` only). Closed: indexed `text/x-perl` and `text/x-ruby`
fixtures into a real Elasticsearch index carrying the production template
mapping, ran the actual compiled Lucene query from `sigma convert` — both
matched. All 6 new entries are now confirmed against both the fixture-level
evaluator AND a real Elasticsearch, not just the former.

**Batch-signature evasion** (security-auditor, MEDIUM: the original
disclosure claimed "real batch droppers overwhelmingly start with one of
these three" with no citation, downplaying a one-keystroke-wide anchor).
Corrected: `@setlocal ...` (a genuinely common real first line) misses
`@set ` by exactly one missing space; a leading blank line or whitespace,
or a `::`/`:LABEL` first line, also evade with zero functional change to
the script. Rewritten in the rule description without the uncited
prevalence claim.

**Python/Perl/Ruby shebang-gating, `.hta`/`text/html`, and LNK-vs-archive
framing** (security-auditor, MEDIUM x3): the original draft disclosed the
batch signature's narrowness but not the shebang signatures' identical
narrowness (no shebang = `text/plain`, invisible); claimed `.hta` was
"covered by an existing detection angle" without checking that angle
(`proc_creation_win_mshta_remote.yml` requires a `CommandLine` argument
this delivery chain doesn't produce, so it does NOT actually fire); and
framed the new LNK entry as covering "the dominant spearphishing vector"
while the same description's own archive-gap paragraph says the dominant
LNK delivery chain wraps the shortcut in an ISO specifically to evade
filters - the entry only covers the non-dominant bare-file case. All three
corrected in the rule description with the specific counterexamples cited
above, not just softened language.

**`falsepositives` and ATT&CK tags** (security-auditor, MEDIUM +LOW): both
rules' `falsepositives:` lists predated this expansion and didn't name the
new match surface's real FP source (provisioning/cloud-init scripts over
plaintext HTTP, not package-manager installs - pip/gem/cpan are HTTPS and
archive-packaged, both opaque to this rule) - added. `attack.t1204.002`/
`attack.t1059.x` were deliberately NOT added to either rule's tags (the
LNK and script entries are each narrower than their named technique) -
this was a correct decision in the first draft but had no recorded
rationale; added one, phrased to avoid literally containing an
`attack.t\d{4}` -shaped string in the description prose, which — caught
during this same verification pass — `scripts/setup/build_attack_coverage.py`
regex-scans the ENTIRE rule file text for (`re.search(r"attack\.(t\d{4}...)")`,
not just the `tags:` block), so an earlier draft mentioning the literal
string `attack.t1059.003` in prose silently reassigned this rule's
coverage-doc technique from T1105 to T1059.003. Caught by re-running
`build_attack_coverage.py --check` before finalizing, not shipped.

## Conclusions

1. **6 new confirmed mime_type entries added** to both
   `net_zeek_executable_download.yml` and `net_zeek_smtp_attachment_
   executable.yml`'s lists, kept in sync per the existing #365 convention:
   `text/x-python`, `text/x-perl`, `text/x-ruby`, `text/x-msdos-batch`,
   `application/x-ms-shortcut`, `application/x-mach-o-executable`.
2. **`text/plain` deliberately NOT added** — matches all 4 extensions in
   the issue's own `.ps1/.bat/.vbs/.js/.wsf` table row that turned out to
   have no distinct Zeek signature (`.ps1`/`.vbs`/`.js`/`.wsf`; `.bat` is
   the one exception in that row — it does have its own signature, see
   above), but is far too broad a bucket to ever function as a specific
   signal at this logsource (matches any plaintext download of any kind).
   Genuinely uncoverable here; needs endpoint telemetry (Sysmon
   ScriptBlockText) instead.
3. **Archive/container formats deliberately NOT addable** — Zeek's file-
   analysis framework has zero signature for ISO9660 (or, by extension,
   the .zip/.7z/.rar formats the issue also named) and doesn't recurse
   into any of them. An absent `mime_type` can never match this rule's
   equality selection — the same structural gap class #382 found for SMTP.
4. **New finding beyond #384's own ask**: a real MSI installer is
   Zeek-indistinguishable from a genuine Word document (`application/
   msword`) — confirmed by Zeek's own signature-source comment
   acknowledging the heuristic is "non-specific and terrible." Deliberately
   not added (would flood on legitimate Word-doc downloads); filed as
   [#417](https://github.com/voltron-1/Suburban_SOC/issues/417).

Full reasoning and citations: `net_zeek_executable_download.yml`'s own
`description:` block carries the operator-facing summary of all of the
above (its SMTP sibling cross-references it rather than duplicating).
