# SOP-003 — Dashboard Operations

> **Scope:** Deploying, verifying, and maintaining the four-dashboard SOC monitoring
> ecosystem (plus the SOC navigation hub) for the Suburban-SOC pipeline.
> **Audience:** SOC operators / pipeline maintainers.
> **Related:** [SOP-001 Pipeline Operations](./SOP-001-pipeline-operations.md) ·
> [SOP-022 Anomaly Validation](./SOP-022-anomaly-validation.md) ·
> [implementation_plan.md](./implementation_plan.md)

---

## 1. Dashboard Inventory

| # | Dashboard | Saved-object ID | Bundle file |
|---|---|---|---|
| 1 | Executive / Bird's-Eye | `executive-dashboard` | `configs/server/executive_dashboard.ndjson` |
| 2 | Network & Traffic | `network-dashboard-v3` | `configs/server/network_dashboard_v3.ndjson` |
| 3 | Endpoint & Host-Level | `endpoint-dashboard` | `configs/server/endpoint_dashboard.ndjson` |
| 4 | Data Quality & Ingestion | `dataquality-dashboard` | `configs/server/dataquality_dashboard.ndjson` |
| 🏠 | SOC Home (Navigation Hub) | `soc-navigation-hub` | `configs/server/soc_navigation_hub.ndjson` |

All visualizations bind to the **`logstash-pattern`** data view (`logstash-*`). The
Executive dashboard's SOAR panels additionally use **`soar-actions-pattern`**
(`soar-actions-*`), which is bundled inside its NDJSON.

---

## 2. Prerequisites

- ELK 9.3.2 stack running (`scripts/setup/docker-compose.yml`): Elasticsearch `:9200`,
  Kibana `:5601`, Logstash `:5044`.
- The enriched `configs/logstash.conf` is the **source of truth**; the deploy script
  syncs it to the Docker mount (`scripts/setup/configs/logstash/logstash.conf`).
- For endpoint data (Dashboard 3): a Winlogbeat (`configs/endpoint/winlogbeat.yml`)
  and/or Filebeat (`configs/endpoint/filebeat_endpoint.yml`) agent shipping to `:5044`.
- For TLS panels (Dashboard 2): `@load base/protocols/ssl` in `configs/zeek/local.zeek`
  (already added) so Zeek emits `ssl.log`.

---

## 3. Deploy / Update

### Linux / WSL / macOS
```bash
./scripts/setup/deploy_dashboards.sh
# Override targets if not on localhost:
ES_URL=http://es-host:9200 KIBANA_URL=http://kbn-host:5601 ./scripts/setup/deploy_dashboards.sh
```

### Windows (PowerShell)
```powershell
.\scripts\setup\deploy_dashboards.ps1
$env:KIBANA_URL = "http://192.168.1.50:5601"; .\scripts\setup\deploy_dashboards.ps1
```

The script: validates ES + Kibana → provisions the `logstash-pattern` data view →
imports all five bundles (`overwrite=true`) → installs Elastic Watchers from
`rules/elastic_watcher/` → syncs `logstash.conf` and restarts Logstash → prints a
summary. Re-running is **idempotent** (overwrite import).

> **Manual import (single dashboard):**
> ```bash
> curl -X POST "http://localhost:5601/api/saved_objects/_import?overwrite=true" \
>   -H "kbn-xsrf: true" --form file=@configs/server/executive_dashboard.ndjson
> ```

---

## 4. Verify Each Dashboard Has Data

1. Open `http://<host>:5601/app/dashboards` and confirm all five appear.
2. Confirm each dashboard ID resolves:
   ```bash
   for id in executive-dashboard network-dashboard-v3 endpoint-dashboard \
             dataquality-dashboard soc-navigation-hub; do
     curl -s "http://localhost:5601/api/saved_objects/dashboard/$id" \
       | grep -o "\"id\":\"$id\"" && echo "  OK $id"
   done
   ```
3. Set the time picker to **Last 24 hours** (or Last 1 hour on the hub).
4. Generate traffic / run `tests/anomaly_simulation/run_all.sh` and confirm panels
   populate (MITRE heatmap + NIST donut on Executive; DNS/HTTP/TLS on Network; Sigma
   hits + auth timeline on Endpoint; ingest rate + agent count on Data Quality).

---

## 5. Data-Source Notes (why a panel may be empty)

| Panel group | Requires |
|---|---|
| MITRE heatmap / NIST donut (Exec) | Logstash Category 5 tags — fire only on matching events (port scan, SSH brute, encoded PowerShell). |
| SOAR Actions / Automated-vs-Manual (Exec) | The AI agent's `log_soar_action()` writing to `soar-actions-*` (triggered by `/alert` calls). |
| DNS / HTTP / TLS panels (Network) | Zeek emitting `dns.log` / `http.log` / `ssl.log`; TLS needs the SSL policy load in `local.zeek`. |
| All Endpoint panels | Winlogbeat/Filebeat agents actively shipping to `:5044`. |
| Agent count / stale agents (Data Quality) | `agent.hostname` populated by Beats agents. |

---

## 6. Adding a New Panel

1. Build the visualization in Kibana (or edit the bundle's NDJSON `visState`).
2. Export: **Stack Management → Saved Objects → select → Export** (include references).
3. Append the exported line(s) to the relevant `configs/server/*.ndjson` and add a
   `panelsJSON` entry + matching `references` entry to the dashboard object.
4. Re-run the deploy script. Keep `logstash-pattern` as the index-pattern reference id.

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| All panels blank | Wrong time range, or no data in `logstash-*` | Widen time picker; confirm ingest on Data Quality dashboard. |
| "Could not locate that data view (id: logstash-pattern)" | Data view not provisioned | Re-run deploy script (step 3 creates it). |
| Import returns `success:false` | Object/version mismatch | Inspect the `errors` array in the response; re-export from a matching Kibana version. |
| TLS / SNI / cipher panels empty | `ssl.log` not generated | Confirm SSL `@load` lines in `local.zeek`; restart Zeek. |
| Endpoint panels empty | No Beats agents shipping | Deploy `winlogbeat.yml` / `filebeat_endpoint.yml`; check `:5044` connectivity. |
| Watcher install warns/fails | Watcher needs trial/Gold license | Start a trial, or use Kibana Rules / the project poller instead. |
| MTTD panel flat | `xpack.security` disabled → no `.alerts-*` | Expected; MTTD is computed externally by `weekly_ciso_report.py`. |

---

## 8. Change Log

| Date | Change |
|---|---|
| 2026-05-29 | Initial SOP — four-dashboard ecosystem + navigation hub deploy/verify procedure. |
