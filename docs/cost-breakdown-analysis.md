# Suburban-SOC — Cost Breakdown Analysis

> **Purpose:** Estimate the total cost of building and operating the Suburban-SOC
> network pipeline, broken into one-time capital expenditure (CapEx) and recurring
> operating expenditure (OpEx), and benchmark it against commercial SOC/SIEM
> alternatives.
>
> **Status:** Planning/reference document. All prices are **illustrative 2026
> estimates** in USD — the repository does not pin specific hardware SKUs, so actual
> figures will vary by vendor, region, and procurement choices. See
> [Assumptions & Disclaimers](#assumptions--disclaimers).

---

## 1. Executive Summary

The Suburban-SOC pipeline is deliberately built on **commodity hardware and a 100%
open-source software stack**, so its cost profile is dominated by one-time hardware
purchases rather than recurring license fees. The only meaningful recurring cost is
**electricity** plus an **optional, usage-based LLM API** for the AI triage agent —
both of which can be driven toward zero with a self-hosted model.

| Metric | Budget tier | Recommended tier | Premium tier |
|---|---:|---:|---:|
| One-time hardware (CapEx) | **~$510** | **~$960** | **~$1,990** |
| Software licensing | **$0** | **$0** | **$0** |
| Annual operating (OpEx) | **~$70/yr** | **~$110/yr** | **~$180/yr** |
| **3-Year TCO** | **~$720** | **~$1,290** | **~$2,530** |

**Bottom line:** A fully functional, automated home/neighborhood SOC can be stood up
for roughly **$500–$1,000** in hardware and run for **~$100/yr**. The equivalent
capability from a managed SIEM or MSSP typically costs **$840–$60,000+ per year**
(see [§7](#7-comparison-vs-commercial-alternatives)), so the DIY approach pays back
its hardware cost in **1–3 months** against any commercial option.

---

## 2. Methodology & Scope

**What's included:** all components required to run the pipeline as architected in the
[README](../README.md) and [network topology](./network_topology.md) — the OpenWrt
mesh (1 gateway + 6 nodes), the SOC host running the Dockerized ELK + Zeek + AI-agent
stack, storage, electricity, and the LLM API consumed by the AI agent
(`scripts/setup/ai_agent/agent_app.py`) and the weekly CISO report
(`weekly_ciso_report.py`).

**Cost categories:**

- **CapEx (one-time):** hardware purchased to build the system.
- **OpEx (recurring):** electricity, LLM API usage, and optional subscriptions.
- **Software licensing:** $0 — every component is free/open-source (see [§4](#4-software-licensing-capex--opex)).

**Two cost lenses:** because the mesh network *is* the home network, much of the
hardware/electricity would exist anyway. Where it matters we distinguish:

- **Total system cost** — everything, as if built from scratch.
- **SOC-incremental cost** — only what the SOC capability *adds* on top of a network
  the household would have regardless (primarily the SOC host + its electricity + API).

---

## 3. Hardware (CapEx, one-time)

Three procurement tiers. The SOC host is the one component with real performance
sensitivity: the ELK stack reserves a **2 GB Elasticsearch heap** and a **512 MB
Logstash heap** (`scripts/setup/docker-compose.yml`), so **16 GB system RAM** is the
practical floor for the Recommended tier.

| Component | Qty | Budget | Recommended | Premium | Notes |
|---|---:|---:|---:|---:|---|
| OpenWrt gateway/mesh controller router | 1 | $80 | $150 | $300 | Must be OpenWrt-compatible w/ packet-capture (tcpdump) support |
| Mesh node APs (OpenWrt) | 6 | $240 ($40 ea) | $360 ($60 ea) | $540 ($90 ea) | Wireless distribution nodes |
| SOC host (Docker: ELK + Zeek + agent) | 1 | $120 | $400 | $700 | Budget = Pi 5 8GB / reused PC; Rec = 16GB mini-PC; Premium = 32GB |
| Primary storage (log retention) | 1 | $40 (500GB SSD) | incl. in host (1TB) | $200 (2TB NVMe + backup) | Sized to retention window |
| Networking misc (cabling, PoE) | — | $30 | $50 | $150 | Cables, optional PoE switch |
| UPS / power protection | — | — | — | $100 | Clean shutdown, surge protection |
| **Hardware subtotal** | | **~$510** | **~$960** | **~$1,990** | |

> **SOC-incremental view:** if the household already owns the mesh router + nodes and
> repurposes an existing PC as the host, incremental hardware CapEx approaches **$0–$120**
> (just storage for log retention).

---

## 4. Software Licensing (CapEx & OpEx)

**Total software licensing cost: $0.** The entire stack is open-source and self-hosted.

| Software | Role | License | Cost |
|---|---|---|---:|
| OpenWrt | Router/AP firmware, packet capture | GPL | $0 |
| Zeek | PCAP → structured JSON IDS engine | BSD | $0 |
| Elasticsearch 9.3.2 | Log storage / indexing | Elastic License (Basic, self-hosted) | $0 |
| Logstash 9.3.2 | Enrichment / routing (GeoIP) | Elastic License (Basic) | $0 |
| Kibana 9.3.2 | Dashboards / visualization | Elastic License (Basic) | $0 |
| Filebeat | Log shipping | Elastic License (Basic) | $0 |
| Docker / Docker Compose | Container runtime | Apache 2.0 / free tier | $0 |
| Python + Flask (AI agent) | SOAR triage webhook | PSF / BSD | $0 |
| ntfy | Mobile push notifications | Apache 2.0 (public server free) | $0 |
| Discord webhooks | SOC channel alerts | Free | $0 |

> ✅ **Resolved — Kibana Watcher.** The SOAR trigger originally used a Kibana Watcher
> (`soar_quarantine_alert`), and Classic **Watcher** is historically an Elastic
> **Gold/Platinum** (paid) feature, *not* part of the free Basic tier — a real licensing
> risk at the time. That Watcher was superseded by an ingest-time HMAC-signed HTTP
> output in `configs/logstash.conf` (a free-tier Logstash feature, no Watcher dependency)
> and, as of [#267](https://github.com/voltron-1/Suburban_SOC/issues/267), fully retired
> (moved to `rules/elastic_watcher/retired/`, historical reference only, no longer
> installed). This analysis's **$0** figure reflects the current, Watcher-free
> architecture, not an assumption about a path not yet taken.

---

## 5. Recurring Operating Costs (OpEx, annual)

### 5.1 Electricity

24/7 always-on power. Assumes a blended **$0.16/kWh** US residential rate (2026 estimate).

| Device | Avg draw | kWh/yr | Cost/yr |
|---|---:|---:|---:|
| SOC host (mini-PC, ~25 W avg) | 25 W | 219 | ~$35 |
| Gateway router (~10 W) | 10 W | 88 | ~$14 |
| 6× mesh nodes (~5 W ea) | 30 W | 263 | ~$42 |
| **Total infrastructure** | **65 W** | **570** | **~$91/yr** |
| **SOC-incremental (host only)** | **25 W** | **219** | **~$35/yr** |

### 5.2 LLM API — usage-based

The AI agent makes one LLM call per high-confidence alert (triage), plus one weekly
CISO report. Default model is `gpt-4` via an OpenAI-compatible endpoint, but the
endpoint is **configurable** (`LLM_API_URL` / `LLM_MODEL`), so cost scales sharply with
model choice. Token assumptions: **triage ≈ 1,200 in / 500 out**, **weekly report ≈
3,000 in / 800 out**.

**Per-call cost by model** (illustrative 2026 per-1M-token pricing):

| Model | $/1M in | $/1M out | Triage call | Weekly report |
|---|---:|---:|---:|---:|
| `gpt-4` (default, premium) | $30.00 | $60.00 | ~$0.066 | ~$0.138 |
| mid-tier (e.g. `gpt-4o`-class) | $2.50 | $10.00 | ~$0.008 | ~$0.016 |
| economy (`*-mini`-class) | $0.15 | $0.60 | ~$0.0005 | ~$0.0009 |
| **Self-hosted (Ollama/local)** | $0 | $0 | **$0** (compute only) | **$0** |

**Annual LLM cost by alert volume** (52 weekly reports/yr included):

| Alert volume | `gpt-4` | mid-tier | economy | local |
|---|---:|---:|---:|---:|
| Low (30/mo · 360/yr) | ~$31/yr | ~$4/yr | ~$0.25/yr | $0 |
| Medium (150/mo · 1,800/yr) | ~$126/yr | ~$15/yr | ~$1/yr | $0 |
| High (600/mo · 7,200/yr) | ~$482/yr | ~$58/yr | ~$4/yr | $0 |

> **Recommendation:** the default `gpt-4` is the single most expensive line item and
> offers little advantage for short triage classifications. Switching `LLM_MODEL` to an
> economy/mid-tier model cuts API cost **~8–100×** with negligible quality loss for this
> task. A self-hosted model (Ollama) zeroes the API entirely at the cost of added compute
> load on the host (favor the Premium host tier or add a GPU).

### 5.3 Optional subscriptions

| Item | Cost/yr | Notes |
|---|---:|---|
| Domain + Dynamic DNS (remote Kibana access) | ~$12 | Optional; LAN-only deployment = $0 |
| ntfy Pro (managed push) | ~$0–$60 | Public ntfy server is free |
| Off-site backup (object storage) | ~$0–$60 | Optional for evidence retention |

### 5.4 Annual OpEx roll-up

| | Budget | Recommended | Premium |
|---|---:|---:|---:|
| Electricity | ~$60 (host + light mesh) | ~$91 | ~$110 |
| LLM API | ~$1 (economy model) | ~$15 (mid-tier) | ~$60 (gpt-4, high vol.) |
| Optional (domain/backup) | $0 | ~$12 | ~$60 |
| **Annual OpEx** | **~$70/yr** | **~$110/yr** | **~$180/yr** |

---

## 6. Total Cost of Ownership (TCO)

| | Budget | Recommended | Premium |
|---|---:|---:|---:|
| Hardware (CapEx, one-time) | $510 | $960 | $1,990 |
| Software licensing | $0 | $0 | $0 |
| Year 1 OpEx | $70 | $110 | $180 |
| **Year 1 total** | **~$580** | **~$1,070** | **~$2,170** |
| **3-Year TCO** | **~$720** | **~$1,290** | **~$2,530** |
| **Effective $/month (3-yr avg)** | **~$20/mo** | **~$36/mo** | **~$70/mo** |

> Hardware refresh is assumed negligible within a 3-year window. The dominant 3-year
> driver is the one-time hardware spend; recurring cost stays under ~$15/month even at
> the Recommended tier.

---

## 7. Comparison vs Commercial Alternatives

Benchmarked at a modest **~1 GB/day** ingest (≈30 GB/month), comparable to this
boundary-scoped pipeline.

| Option | Pricing model | Est. annual cost | Notes |
|---|---|---:|---|
| **Suburban-SOC (this project, Recommended)** | One-time HW + electricity + tiny API | **~$110/yr** (after ~$960 HW) | Self-hosted, full data ownership |
| Microsoft Sentinel | ~$2.30/GB ingest + retention | **~$840–$1,200/yr** | Cloud SIEM, pay-as-you-go |
| Elastic Cloud (managed) | Hosted ELK, from ~$95/mo | **~$1,140–$3,000/yr** | Same stack, managed/hosted |
| Splunk Cloud | Ingest/workload pricing | **~$1,800–$15,000+/yr** | Enterprise SIEM, premium tier |
| Managed MSSP / SOC-as-a-Service | Monthly retainer | **~$12,000–$60,000+/yr** | Includes human analysts |

**Break-even:** the Recommended-tier hardware (~$960) is recovered versus the *cheapest*
managed option (Sentinel, ~$70–$100/mo) in roughly **1–3 months**. Every month
thereafter, the DIY pipeline runs at a fraction of the recurring cost — the trade-off
being that operations, tuning, and analyst time are provided by the project team rather
than a vendor.

---

## 8. Cost-Optimization Recommendations

1. **Right-size the LLM model.** Change `LLM_MODEL` from the default `gpt-4` to an
   economy/mid-tier model — the largest single OpEx lever (**~8–100× reduction**).
2. **Consider a self-hosted LLM (Ollama).** Eliminates API cost entirely; best paired
   with the Premium host tier (more RAM / optional GPU).
3. **Repurpose existing hardware.** Using an owned PC as the SOC host and an existing
   mesh drops incremental CapEx to near **$0–$120**.
4. **Confirm the free-tier alerting path.** Avoid an accidental Elastic Gold dependency
   from Kibana **Watcher** — use Kibana Rules or the project poller to stay at $0
   (see [§4](#4-software-licensing-capex--opex) warning).
5. **Tune log retention & ILM.** Boundary-only HTTP scoping already limits volume; apply
   Elasticsearch ILM to cap disk growth and defer larger-storage purchases.
6. **Batch/throttle alert triage.** De-duplicate repeat alerts before invoking the LLM to
   keep per-alert API calls (and cost) proportional to *distinct* events.

---

## 9. Assumptions & Disclaimers

- All prices are **illustrative 2026 USD estimates**; the repository does not specify
  hardware SKUs or a fixed LLM provider/model, so real costs will vary by vendor, region,
  procurement, and provider pricing changes.
- Electricity assumes **$0.16/kWh** and continuous 24/7 operation; actual rates vary
  widely by region and time-of-use plan.
- LLM costs assume the token sizes stated in [§5.2](#52-llm-api--usage-based); real prompt
  sizes and alert volumes will differ. Provider list prices change frequently — re-validate
  before budgeting.
- Commercial comparison figures are **order-of-magnitude** estimates at ~1 GB/day ingest
  and exclude negotiated discounts and free tiers.
- This analysis excludes **labor/development time** (the project was built as a student
  course deliverable) and any **internet service**, which is treated as a pre-existing
  household cost.

---

*Generated for the Suburban-SOC project. Update the figures as hardware is finalized and
the LLM provider/model is locked in.*
