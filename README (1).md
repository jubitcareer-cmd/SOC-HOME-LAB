# Home SOC Lab: End-to-End Security Monitoring and Alert Scoring

A home Security Operations Center (SOC) lab that collects endpoint security events, monitors file integrity, tracks network devices, scores alerts with a rule-based analysis service, and presents everything on a single Grafana dashboard.

**Stack:** Wazuh · Grafana · NetAlertX · Python (Flask/Waitress) · systemd · Docker · UFW · Ubuntu · Windows

> Built following the implementation guide by *The Social Dork | Cybersecurity*, then adapted to my own network, debugged and extended. Credit to the original author for the architecture.

---

## Architecture

```
 Windows laptop                         Ubuntu VM
 ┌──────────────────┐   agent events   ┌─────────────────────────────┐
 │ Wazuh agent      │ ───TCP 1514────▶ │ Wazuh Manager + Indexer     │
 │ (FIM, registry)  │                  │ NetAlertX (Docker)          │
 │                  │                  │ Alert analysis helper       │
 │ Grafana          │ ◀──queries────── │  (Python, systemd, :8010)   │
 │  OpenSearch plug │   9200/20212/    └─────────────────────────────┘
 │  Infinity plug   │   8010
 └──────────────────┘
```

| Component | Host | Purpose |
|---|---|---|
| Wazuh agent | Windows | Produces file-integrity (FIM) and security events |
| Wazuh Manager + Indexer | Ubuntu VM | Receives, analyses and indexes events |
| NetAlertX | Ubuntu VM (Docker) | Network device discovery and inventory |
| Analysis helper | Ubuntu VM (systemd) | Tails Wazuh alerts, scores each FIM event with local rules, exposes results over a key-protected REST API |
| Grafana | Windows | Dashboard using OpenSearch and Infinity data sources |

## What the dashboard shows

- **Latest risk score** (gauge) and **latest alert name**
- **Latest analysis summary** with recommended analyst actions
- **Analysis history** (searchable table of every scored event)
- **File integrity events** (added / modified / deleted, per agent)
- **FIM event count** over the last 24 hours
- **Network device inventory** (name, IP, MAC, type, online/offline status)

<!-- Add screenshots here -->
<!-- ![Dashboard](docs/images/dashboard-overview.png) -->

## How it works

1. The Wazuh agent on Windows monitors a directory in real time and reports `added`, `modified` and `deleted` events to the Wazuh Manager.
2. The Manager writes alerts to `alerts.json` and the Indexer makes them searchable.
3. A Python service running under systemd tails the alert file, filters for syscheck (FIM) events, scores each one, stores the result as JSONL, and serves it through a small authenticated API (`/health`, `/api/latest`, `/api/analyses`).
4. Grafana reads Wazuh data through the OpenSearch plug-in and the helper and NetAlertX APIs through the Infinity plug-in.

## Scoring logic

The helper scores every file-integrity event locally with transparent rules, so no event data leaves the network and results are explainable.

| Factor | Points |
|---|---|
| Base: added / modified / deleted | 10 / 15 / 15 |
| Wazuh rule level | up to +15 |
| Startup folder or hosts file | +35 |
| `system32`, `syswow64`, scheduled tasks folder | +30 |
| `Program Files` / `ProgramData` | +15 / +10 |
| Executable or script (`.exe .dll .sys .scr .ps1 .vbs`) | +25 |
| `.bat .cmd .msi` / `.js .lnk .jar` | +20 / +15 |
| Deleted file that was already flagged | +10 |

Severity bands: 0-29 Low, 30-49 Guarded, 50-69 Medium, 70-84 High, 85-100 Critical. Each record stores the evidence list and recommended analyst actions. The score is a triage aid, not a verdict, and the summary says so.

## Security practices applied

- Dedicated **read-only** Wazuh Indexer user for Grafana (no admin account in dashboards)
- TLS verification with the Indexer CA certificate, with the certificate SAN containing the server IP
- Helper API protected by an `X-API-Key` header, compared with a constant-time check
- Helper runs as a **non-login system user** with systemd hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `ReadOnlyPaths`, `PrivateTmp`)
- Secrets kept in a root-only (`0600`) environment file, never in code
- UFW rules limiting service ports to the Grafana host
- All scoring runs locally, so no file paths or event data are sent to external services
- API keys rotated after exposure

## Problems I solved

| Problem | Cause | Fix |
|---|---|---|
| Grafana: "Validation error, invalid URL" | Malformed base URL, and health check URL appended to the base URL | Corrected URLs; used a relative `/health` path |
| Device table columns empty | Field selectors are case-sensitive; this NetAlertX version uses `devMac`, `devLastIP` | Read real keys from Query Inspector JSON and corrected selectors |
| JQ vs JSONata errors | Leading-dot syntax only valid with the JQ backend parser | Selected Backend → JQ for `.devices[]` |
| Device status showed `0/1` | Version exposes `devPresentLastScan` instead of a status string | Computed an Online/Offline field in JQ and added colour mappings |
| Table rendered blank although data existed | Wrap text on a large table | Disabled wrap text; verified with Table view and Query Inspector |
| All helper panels blank after key rotation | Grafana still sent the old key (HTTP 401) | Updated the data source header and re-tested |
| Registry events flooding the FIM view | Agent also monitored registry keys | Filtered with Lucene `NOT syscheck.path:HKEY*` |
| Port 8010 already in use check | Needed to confirm before binding | Verified with `ss -ltnp` that it was the helper itself |

## Validation

Created, modified and deleted a test file on Windows and confirmed:

- All three events appear in the Wazuh index and the Grafana FIM table
- The helper stored one analysis per event
- Risk gauge, alert name, summary and history panels updated within the 30 s refresh

## Repository contents

```
.
├── README.md
├── dashboard/network-security-dashboard.json   # exported Grafana dashboard (no secrets)
├── helper/wazuh_airia_forwarder.py             # alert tailer and API (secrets via env vars)
├── helper/wazuh-airia-forwarder.service        # systemd unit
├── helper/forwarder.env.example                # placeholders only
└── docs/images/                                # screenshots
```

> Before publishing: remove real API keys, tokens, passwords, certificates and any personal paths or usernames. Never commit the real `.env` file.

## Skills demonstrated

SIEM deployment and tuning · File Integrity Monitoring · log pipeline design · REST API design · Linux service hardening (systemd, UFW) · Docker · Grafana dashboarding · Lucene and JQ querying · troubleshooting and root-cause analysis · security documentation

## Credits

Architecture and original implementation guide: *The Social Dork | Cybersecurity*. The guide's helper calls a cloud AI agent; this version replaces that call with a local rule-based scorer. Network and address adaptation, debugging, dashboard build, validation and documentation: this repository.
