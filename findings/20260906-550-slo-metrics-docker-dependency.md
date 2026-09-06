# #550 — slo-metrics.service dies 203/EXEC when Docker Desktop stops

Investigation date: 2026-09-06. Host: Dragon-Zord (local WSL capture host).
Scope: root-cause confirmation for #550 (M26) before any fix.

## 1. Root cause — CONFIRMED

`configs/systemd/slo-metrics.service:100` is the only ES-CA-extracting
`ExecStartPre` in the repo without a `-` prefix:

```
configs/systemd/slo-metrics.service:100  ExecStartPre=/usr/bin/docker cp elasticsearch:...  <-- no '-'
configs/systemd/intel-refresh.service:121  ExecStartPre=-/usr/bin/docker cp elasticsearch:...
configs/systemd/checkpoints-compact.service:94  ExecStartPre=-/usr/bin/docker cp elasticsearch:...
configs/systemd/threat-intel-compact.service:81  ExecStartPre=-/usr/bin/docker cp elasticsearch:...
```

`/usr/bin/docker` is a symlink into the Docker Desktop WSL distro and dangles
whenever that distro is Stopped:

```
lrwxrwxrwx 1 root root 48 Sep  5 16:46 /usr/bin/docker -> /mnt/wsl/docker-desktop/cli-tools/usr/bin/docker
```

### Empirical proof of the `-`-prefix semantics

Two throwaway `--user` units on this exact host, `ExecStartPre` pointing at a
path that does not exist (identical failure class to a dangling symlink):

| Unit | Directive | Result | ExecStart reached |
|---|---|---|---|
| `soc550-dashtest` | `ExecStartPre=-/nonexistent/dangling-docker cp a b` | `Result=success` | **yes** (`REACHED_EXECSTART`) |
| `soc550-nodashtest` | `ExecStartPre=/nonexistent/dangling-docker cp a b` | `Result=exit-code`, `status=203/EXEC` | **no** |

Verbatim from the control unit's journal:

```
soc550-nodashtest.service: Control process exited, code=exited, status=203/EXEC
soc550-nodashtest.service: Failed with result 'exit-code'.
```

This is byte-for-byte the failure recorded in #550. Both probe units were
removed after the test.

## 2. The `-` prefix alone is NOT sufficient for this unit

`RuntimeDirectory=suburban-soc-slo` is torn down between every `Type=oneshot`
run, so `/run/suburban-soc-slo/ca.crt` does not survive. With only a `-`
prefix added, a Docker-down run reaches `ExecStart` but `ES_CA` points at a
file that does not exist, so `requests` raises a **TLS CA bundle** error for
every ES call. The operator reading the journal is told the CA is missing
when the actual fact is that Elasticsearch is down. The degraded mode needs a
CA copy persisted under `StateDirectory=` (`/var/lib/suburban-soc-slo/`, which
already holds `ca_fingerprint.sha256`) so the error the run reports is the
true one.

## 3. Two further live breaks found in the same lane — NOT #550

Both are independent of Docker and of #550's fix. Together with #550 they are
why the 2026-08-31 → 09-05 blackout produced zero signal.

### 3a. `slo_metrics` ES credential fails authentication right now

Docker Desktop is **Running**, all six containers are up, and the `docker cp`
step succeeded (`code=exited, status=0/SUCCESS`) — yet the 09:06:26 run still
failed, at the Python, with HTTP 401:

```
-> slo_metrics_reader privilege self-check failed: privilege self-check returned HTTP 401:
   {"error":{"root_cause":[{"type":"security_exception","reason":"unable to authenticate user
   [slo_metrics] for REST request [/_security/user/_has_privileges]" ...
-> ES index failed: HTTP 401 ... [/soc-slo-metrics/_doc]
```

The ES user itself exists and is enabled:

```
{"slo_metrics":{"username":"slo_metrics","roles":["slo_metrics_reader"],
 "full_name":"SLO metrics (Suburban-SOC)","email":null,"metadata":{},"enabled":true}}
```

So `SLO_METRICS_PASSWORD` in `scripts/setup/.env` no longer matches the
password held in Elasticsearch. Every ES-backed metric is
`ERROR(unmeasurable)`, nothing is indexed to `soc-slo-metrics`, and the unit
exits 3. **The SLO dashboard has been reading a frozen index for as long as
this has held.** Fixing #550 does not fix this.

### 3b. No notification sink is configured on this host

`scripts/setup/ai_agent/slo_metrics.py:150` — `NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "")`,
and the alert block at line 1969 is gated on `... and NTFY_TOPIC`.
`scripts/setup/.env` on this host contains **no `NTFY_TOPIC` key at all**
(`grep -c NTFY scripts/setup/.env` → `0`), while `.env.example:112` ships it
empty. So the outbound alert never fires here regardless of breach state.

Note the run *did* correctly classify the sensor lane as breaching —
`zeek_ingest_lag_seconds ... BREACH(no-data)` (`BREACH_IF_NA`) — it simply had
nowhere to send it.

## 4. Correlated-failure summary

| Control | State during the 08-31 → 09-05 blackout | Independent of the others? |
|---|---|---|
| `zeek-host-capture.service` | wedged `active (running)`, 0 packets | — (the thing being watched) |
| `slo-metrics.service` | dead `203/EXEC` (this issue) | **no** — shares Docker Desktop with the sensor |
| `slo_metrics` ES credential | 401 (3a) | yes, but silent |
| ntfy alert path | unconfigured (3b) | yes, but silent |

Three independent single points of failure, all silent, all in the one lane
whose job is to notice silence.

## 5. Fix shape for #550 (this issue only)

1. `-`-prefix the `docker cp` in `slo-metrics.service`, matching the other
   three units. Update the two in-file comments that currently justify the
   absent prefix (they cite the `docker cp` as precedent for the verify step
   also being hard-failing).
2. Persist a fingerprint-verified CA copy under `StateDirectory=` and restore
   from it when the `docker cp` could not run, so the degraded run reports the
   real reason ES is unreachable instead of a CA-bundle error.
3. `StateDirectoryMode=0700` — that directory now holds a trust anchor as well
   as its pin; `RuntimeDirectoryMode=0700` is already set for the same reason.
4. New `tests/pipeline/` check asserting the `-` prefix and the cache wiring,
   so this cannot regress. The existing `test_es_ca_fingerprint_pinning.py`
   assertions (cp before verify, verify not `-`-prefixed, both paths present)
   are preserved by the shape above.

3a and 3b are **out of scope for #550** and need their own issues: 3a is a
host `.env`/ES credential resync (owner action — this session must not rotate
a live stack credential unasked), 3b is a one-key `.env` addition plus a
decision on which topic to publish to.
