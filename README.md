# M-NIDS — Multi-Layer Network Intrusion Detection System

M-NIDS: A Multi-Layer Hybrid Network Intrusion Detection System Combining Signature-Based and Unsupervised Machine Learning
Final Graduation Project

![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04_LTS-E95420?style=flat&logo=ubuntu&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=flat&logo=postgresql&logoColor=white)
![Snort](https://img.shields.io/badge/Snort-3.x-FF0000?style=flat)
![scikit--learn](https://img.shields.io/badge/scikit--learn-IsolationForest-F7931E?style=flat&logo=scikitlearn&logoColor=white)
![nfstream](https://img.shields.io/badge/nfstream-Flow_Extraction-4B8BBE?style=flat)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat&logo=fastapi&logoColor=white)
![Nginx](https://img.shields.io/badge/Nginx-Reverse_Proxy-009639?style=flat&logo=nginx&logoColor=white)
![n8n](https://img.shields.io/badge/n8n-latest-EA4B71?style=flat&logo=n8n&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## Table of Contents

- [Overview](#overview)
- [Why Multi-Layer?](#why-multi-layer)
- [Lab Topology](#lab-topology)
- [Architecture](#architecture)
- [Detection Layers](#detection-layers)
  - [Layer 1 — Snort (Signature-Based)](#layer-1--snort-signature-based)
  - [Layer 2 — Isolation Forest: Exfiltration Model](#layer-2--isolation-forest-exfiltration-model)
  - [Layer 3 — Isolation Forest: Scan/Persistent Model](#layer-3--isolation-forest-scanpersistent-model)
- [Why This Design](#why-this-design)
- [Project Structure](#project-structure)
- [Components](#components)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Nginx Configuration](#nginx-configuration)
- [Database Schema](#database-schema)
- [Environment Variables](#environment-variables)
- [API Endpoints](#api-endpoints)
- [Telegram Alerting with n8n](#telegram-alerting-with-n8n)
- [Testing & Validation](#testing--validation)
- [Known Limitations](#known-limitations)
- [Security Notes](#security-notes)
- [Roadmap](#roadmap)
- [Authors](#authors)

---

## Overview

M-NIDS is a full-stack, multi-layer Network Intrusion Detection System built as a graduation project. It combines a traditional **signature-based engine (Snort 3)** with two **unsupervised machine-learning layers (Isolation Forest)** built on top of **nfstream** flow extraction, so that the system can catch both known attack signatures *and* behavioral anomalies that signatures alone would miss — such as data exfiltration over legitimate protocols (including encrypted ones like SSH/SCP) and slow, low-and-slow port scans.

Alerts from every layer converge into a single **PostgreSQL** store, are served through a **FastAPI** backend, visualized on a real-time **React** dashboard, and pushed to **Telegram** via **n8n**, using PostgreSQL's native `LISTEN/NOTIFY` for push-based (no-polling) alerting. **Nginx** sits in front of everything as the single public entry point.

**WebGoat** is used as a deliberately vulnerable target application, and attacks are simulated from a dedicated **Kali Linux** VM.

---

## Why Multi-Layer?

Signature-based detection is precise but blind to anything without a matching rule. During testing, Snort correctly caught a high-volume connection-rate flood (an existing DoS rule matched) but **missed** a slow port scan, a bulk-transfer exfiltration test, and an SSH/SCP-based exfiltration test entirely — because none of these produced payloads or patterns that matched a known signature.

That gap is exactly what the two Isolation Forest layers are designed to close:

- One model watches **individual flows** for volumetric/behavioral outliers (exfiltration).
- The other watches **windowed, per-source-IP aggregates** for reconnaissance-style behavior (scanning, persistent/unusual connection patterns) that no single flow would reveal on its own.

Running signature-based and behavior-based detection side by side is the core argument of the project: each layer catches what the other structurally cannot.

---

## Lab Topology

The system runs inside an isolated VirtualBox lab on a private `intnet`, so no attack traffic ever touches a real network:

| VM | Role | IP |
|---|---|---|
| Ubuntu Server | Runs the full Docker Compose stack | `10.10.10.1` |
| Kubuntu | Normal user / baseline traffic generator | `10.10.10.2` |
| Kali Linux | Attacker | `10.10.10.3` |

---

## Architecture

```
                         Isolated intnet (VirtualBox, no external access)
   Kubuntu (10.10.10.2)              Kali Linux (10.10.10.3)
   normal/baseline traffic           attack simulation
              \                              /
               \                            /
                v                          v
          +----------------------------------------+
          |     Ubuntu Server VM (10.10.10.1)       |
          |                                          |
          |  +------------------------------------+  |
          |  |  Snort 3                            |  |
          |  |  interface: enp0s3                  |  |
          |  |  network_mode: host                 |  |
          |  |  --> alert_json.txt                 |  |
          |  +------------------+-------------------+  |
          |                     |                     |
          |         +-----------+-----------+          |
          |         |  alerts_watcher       |          |
          |         |  tails alert_json.txt |          |
          |         |  HTTP POST -->        |          |
          |         |  /api/alerts/ingest   |          |
          |         +-----------+-----------+          |
          |                     |                     |
          |   +-----------------+------------------+   |
          |   |     nfstream (live flow capture)   |   |
          |   +-----------------+------------------+   |
          |                     |                     |
          |     +---------------+---------------+      |
          |     |     ml_detector.py (1 process, |      |
          |     |     parallel checker threads)  |      |
          |     |                                 |      |
          |     |  Thread A: isolation_forest     |      |
          |     |  (per-flow, exfiltration model) |      |
          |     |  batches alerts every 10s       |      |
          |     |                                 |      |
          |     |  Thread B: scan_persistent      |      |
          |     |  (60s windowed, per-src-IP)      |      |
          |     +---------------+-----------------+      |
          |                     |                     |
          |                     v                     |
          |            +------------------+           |
          |            |   FastAPI backend |          |
          |            |   /api/alerts/*    |          |
          |            +--------+----------+           |
          |                     |                     |
          |                     v                     |
          |            +------------------+           |
          |            |  PostgreSQL 15    |          |
          |            |  event table       |          |
          |            |  NOTIFY trigger    |          |
          |            +--------+----------+           |
          |                     |  LISTEN/NOTIFY        |
          |                     |  (channel: new_event) |
          |                     v                     |
          |            +------------------+           |
          |            |   n8n --> Telegram |          |
          |            +------------------+           |
          |                                          |
          |   +----------------+   +---------------+  |
          |   | React Frontend |   |   WebGoat      |  |
          |   | (dashboard)    |   |   (target app)  |  |
          |   +--------+-------+   +---------------+  |
          |            |                              |
          |   +--------+---------------------------+  |
          |   |   Nginx (reverse proxy) :80          |  |
          |   |   /       --> frontend:80            |  |
          |   |   /api/   --> backend:8000/api/      |  |
          |   |   /n8n/   --> n8n:5678/ (WS upgrade) |  |
          |   +---------------------------------------+  |
          +------------------------------------------+

Client access (single entry point):
  Browser --> Nginx (:80) --> React Frontend / FastAPI Backend / n8n
```

---

## Detection Layers

### Layer 1 — Snort (Signature-Based)

Runs with `network_mode: host` on interface `enp0s3` for direct NIC access, matching traffic against `snort/rules/local.rules`. Writes newline-delimited JSON alerts to `alert_json.txt`, which `alerts_watcher` tails and forwards to the backend via `POST /api/alerts/ingest` (not direct database writes — this keeps Snort fully decoupled from the database, so it never waits on a write and the watcher can restart independently without dropping alerts).

### Layer 2 — Isolation Forest: Exfiltration Model

Detects **volumetric/behavioral outliers on individual flows** — data exfiltration over any protocol, including encrypted ones.

- **Features:** 25 per-flow features from nfstream, grouped into five categories — traffic volume, directional asymmetry, packet size distribution, packet inter-arrival time (PIAT) distribution, and TCP flags.
- **Flow settings:** `MIN_BIDIRECTIONAL_PACKETS=3`, `IDLE_TIMEOUT=10s`, `ACTIVE_TIMEOUT=30s`.
- **Training:** `IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)` with `StandardScaler`, trained on nfstream-extracted flows from manually captured (`tcpdump`) normal and heavy-browsing baseline traffic — including background SSH sessions, kept deliberately to show that long-lived connections aren't inherently anomalous.
- **Preprocessing:** `X = df[FEATURE_COLUMNS].fillna(0).replace([inf, -inf], 0)`, then scaled.
- **Decision threshold:** anomaly score `< -0.10` (empirically validated — see [Testing & Validation](#testing--validation)).
- **Outputs:** `isolation_forest.joblib`, `scaler.joblib`, `feature_list.txt`, `model_version.json`.
- **Runtime:** evaluated on every flow unconditionally (independent of the scan_persistent window verdict — see the bug fix below), alerts batched every `ALERT_BATCH_SECONDS=10s`.

A feature-correlation heatmap over the 25 features showed several near-perfectly correlated groups (e.g. `bidirectional_duration_ms` ≈ `src2dst_duration_ms` ≈ `dst2src_duration_ms`; the three packet-count features ≈1.00 correlated), while others such as `bidirectional_min_piat_ms` were largely independent — informative context for the committee on feature redundancy, even though all 25 were kept for training.

### Layer 3 — Isolation Forest: Scan/Persistent Model

Detects **reconnaissance-style behavior** the per-flow model structurally cannot see: slow port scanning and unusual/persistent long-lived connection patterns — by aggregating flows per source IP over a rolling window instead of scoring flows individually.

- **Windowing:** 60-second windows (`WINDOW_SECONDS=60`), aggregated via `groupby(["src_ip", "window"])` over nfstream flows.
- **Features (10, final):** `unique_dst_ports`, `unique_dst_ips`, `total_flows`, `failed_ratio`, `port_diversity_rate`, `connection_rate`, `avg_flow_duration`, `max_flow_duration`, `std_flow_duration`, `avg_bytes`.
  - `failed_ratio = failed_count / total_flows`, where a failed flow is defined as `(SYN sent, ACK == 0)` or `RST >= 1`.
  - `port_diversity_rate = unique_dst_ports / total_flows`.
  - `connection_rate = total_flows / WINDOW_SECONDS`.
  - `std_flow_duration.fillna(0)`.
- **Training:** `IsolationForest(n_estimators=200, contamination="auto", random_state=42)` with `StandardScaler`, saved as `scan_persistent_model.joblib` / `scan_persistent_scaler.joblib`.
- **Decision threshold:** anomaly score `< -0.10`, same boundary as the exfiltration model.
- **Runtime:** evaluated per 60s window per source IP, in parallel with the per-flow checker.

> **Detection layer independence bug fix:** the per-flow model originally only ran on flows in windows *not* already flagged by `scan_persistent`, which made the two layers mutually exclusive instead of independent — `scan_persistent` appeared to "catch" exfiltration only because it absorbed every flow in an anomalous window under one alert. Fixed by making `evaluate_per_flow()` run unconditionally on every flow regardless of the window verdict, and the `SCAN_THRESHOLD` default was corrected from `-0.15` to `-0.10` to match the validated threshold.

---

## Why This Design

### Why Snort with `network_mode: host`?

Snort needs direct access to the physical network interface to capture packets before any Docker NAT or bridge processing occurs. `network_mode: host` gives the container full visibility over the host NIC while every other service remains isolated inside the bridge network.

### Why HTTP ingest instead of direct database writes from alerts_watcher?

Routing all alerts — Snort's and both ML models' — through a single `POST /api/alerts/ingest` endpoint on the backend keeps the ingestion path uniform and decoupled: no detection component talks to PostgreSQL directly, so the schema and validation logic live in one place.

### Why nfstream for flow extraction?

nfstream turns raw packets into bidirectional flow records with rich statistical features (duration, packet/byte counts, PIAT, TCP flags) out of the box, which is what both Isolation Forest models are trained and scored on — avoiding a hand-rolled flow-reconstruction pipeline.

### Why Isolation Forest, and why two of them?

Isolation Forest is unsupervised, so it needs no labeled attack data — only a baseline of normal traffic — which fits a lab where "attacks" are simulated rather than naturally occurring. A single per-flow model cannot see aggregate, cross-flow behavior like scanning; splitting detection into a per-flow model (exfiltration) and a windowed, per-source-IP model (scan/persistent) lets each specialize in the anomaly shape it can actually see.

### Why n8n for alerting instead of custom code?

n8n listens to PostgreSQL's native `LISTEN/NOTIFY` channel, which means notifications fire the moment a row is inserted — no polling delay. The visual workflow editor also makes it straightforward to extend alerting to other channels (Slack, email, webhooks) without modifying application code.

### Why PostgreSQL?

PostgreSQL's native `INET` type stores IP addresses cleanly and efficiently. The `LISTEN/NOTIFY` mechanism enables real-time push notifications to n8n without any polling overhead.

### Why Nginx as a reverse proxy?

Nginx exposes a single public entry point on port 80 and routes requests by path: `/` to the React frontend, `/api/` to the FastAPI backend, and `/n8n/` to the n8n editor — with WebSocket upgrade headers enabled so n8n's real-time UI keeps working behind the proxy. Every other internal service stays unreachable from outside the Docker network, centralizing routing and minimizing the attack surface of the dashboard layer.

---

## Project Structure

```
mpu-project01/
├── docker-compose.yml
├── init.sql                        # Schema — runs automatically on first PostgreSQL start
├── .env                            # NOT in git
├── .gitignore
├── README.md
├── Dockerfile.watcher               # alerts_watcher container image
├── alerts_watcher.py                # Tails alert_json.txt, POSTs to /api/alerts/ingest
│
├── snort/
│   ├── snort.lua                    # Snort 3 configuration
│   ├── entrypoint.sh                # Snort startup script
│   └── rules/
│       └── local.rules
│
├── snort_logs/                      # Shared volume: Snort writes, alerts_watcher reads
│   └── alert_json.txt
│
├── ml/
│   ├── ml_detector.py               # Unified detector — parallel checker threads
│   ├── models/
│   │   ├── isolation_forest.joblib
│   │   ├── scaler.joblib
│   │   ├── feature_list.txt
│   │   ├── model_version.json
│   │   ├── scan_persistent_model.joblib
│   │   └── scan_persistent_scaler.joblib
│   └── training/
│       ├── train_isolation_forest.py
│       └── train_scan_persistent.py
│
├── n8n_data/                        # n8n persistent workflow storage
│
├── nginx/
│   ├── nginx.conf                   # Reverse proxy configuration (/, /api/, /n8n/)
│   └── Dockerfile
│
└── dashboard/
    ├── backend/
    │   ├── Dockerfile
    │   ├── requirements.txt
    │   ├── main.py
    │   ├── database.py
    │   └── routes/
    │       ├── alerts.py            # /api/alerts/snort, /api/alerts/ingest
    │       └── stats.py             # /api/stats/*
    └── frontend/
        ├── Dockerfile
        └── src/
            ├── App.js
            ├── api/
            │   └── index.js
            └── components/
                ├── StatsCards.js
                ├── SnortAlerts.js
                └── ProtocolChart.js
```

---

## Components

### Snort 3 (`ciscotalos/snort3` — `network_mode: host`)

- Signature-based detection engine using rules from `snort/rules/local.rules` on interface `enp0s3`
- Runs with `network_mode: host` and `privileged: true` for direct NIC access
- On rule match: appends a JSON object to `snort_logs/alert_json.txt`
- Has no database dependency — writes only to the shared volume

### alerts_watcher (Python)

- Tails `alert_json.txt` using a persistent file position cursor (survives restarts)
- Forwards each parsed alert to the backend via `POST /api/alerts/ingest`

### ml_detector.py (Python — unified process)

- One process running two checker loops in parallel threads, both reading live nfstream flows
- **Thread A:** per-flow `isolation_forest` (exfiltration model), evaluated unconditionally on every flow, alerts batched every 10s
- **Thread B:** `scan_persistent` model, evaluated per 60s window per source IP
- Both threads post alerts to the backend under the same schema, distinguished by a `detection_layer` field
- `AlertIngest` schema requires `source_type="ml_model"`, `anomaly_score`, and `model_version`; `features_snapshot` and `is_anomaly` are optional

### PostgreSQL 15

- Persistent storage for all alerts via the `event` and `signature` tables
- `LISTEN/NOTIFY` trigger on the `event` table fires instantly on every INSERT
- Schema initialized automatically from `init.sql` on first start
- Port 5432 exposed on the host for local development access

### n8n (internal port `5678`)

- Workflow automation engine connected to PostgreSQL via `LISTEN/NOTIFY`
- Listens on the `new_event` notification channel
- On each new alert: formats a structured message and delivers it to a Telegram bot
- Reachable through Nginx at `/n8n/`, with WebSocket upgrade support for the live editor UI
- Workflow state persisted in `./n8n_data`

### FastAPI Backend (internal port `8000`)

- REST API reading from and writing to PostgreSQL
- Single ingest endpoint (`/api/alerts/ingest`) shared by Snort/alerts_watcher and both ML detector threads
- Reachable through Nginx at `/api/`
- Auto-generated interactive docs at `/api/docs`

### React Frontend (internal port `80`)

- Real-time dashboard polling FastAPI every 500ms
- Displays: stats cards, alerts table (with port/service mapping and priority filters), protocol distribution chart, real-time alert frequency chart
- Sticky headers on scrollable tables
- Served internally on port 80, reachable through Nginx at `/`

### Nginx (port `80`)

- Reverse proxy and single public entry point for the whole stack
- `location /` → `proxy_pass http://frontend:80`
- `location /api/` → `proxy_pass http://backend:8000/api/`
- `location /n8n/` → `proxy_pass http://n8n:5678/`, with `Upgrade`/`Connection` headers and `proxy_buffering off` for n8n's WebSocket-based editor
- Forwards `Host`, `X-Real-IP`, and `X-Forwarded-For` headers to preserve client info upstream

### WebGoat

- Deliberately vulnerable Java web application used as an attack target
- Ports 8080 and 9090

---

## Prerequisites

| Requirement    | Version   | Check Command            |
| -------------- | --------- | ------------------------ |
| Ubuntu         | 24.04 LTS | `lsb_release -a`         |
| Docker CE      | 24.x+     | `docker --version`       |
| Docker Compose | v2.x+     | `docker compose version` |
| RAM            | 8 GB+     | `free -h`                |
| Storage        | 20 GB+    | `df -h`                  |

Lab requires a VirtualBox setup with three VMs on an isolated internal network (`intnet`): the Ubuntu Server VM running the Docker stack, a Kubuntu VM for baseline/normal traffic, and a Kali Linux VM for attack simulation.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-username/mpu-project01.git
cd mpu-project01

# 2. Create the environment file
cp .env.example .env

# 3. Create required directories
mkdir -p snort_logs n8n_data

# 4. Start all services
docker compose up -d

# 5. Verify all containers are running
docker compose ps

# 6. Simulate attacks from Kali Linux (10.10.10.3)
nmap -sS <server-ip>
nikto -h http://<server-ip>:8080

# 7. Open the dashboard (through Nginx)
# http://localhost

# 8. Open n8n (through Nginx)
# http://localhost/n8n/

# 9. Open API docs (through Nginx)
# http://localhost/api/docs
```

---

## Nginx Configuration

`nginx/nginx.conf`:

```nginx
server {
    listen 80;
    server_name localhost;

    location / {
        proxy_pass http://frontend:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /api/ {
        proxy_pass http://backend:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /n8n/ {
        proxy_pass http://n8n:5678/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_cache_bypass $http_upgrade;
    }
}
```

---

## Database Schema

```sql
CREATE SEQUENCE IF NOT EXISTS event_cid_seq START 1;

CREATE TABLE IF NOT EXISTS event (
    sid           INT NOT NULL,
    cid           INT NOT NULL DEFAULT nextval('event_cid_seq'),
    signature     TEXT,
    signature_gen INT,
    signature_id  INT,
    signature_rev INT,
    timestamp     TIMESTAMP NOT NULL,
    ip_src        INET,
    ip_dst        INET,
    layer4_sport  INT,
    layer4_dport  INT,
    ip_proto      INT,
    priority      INT,
    class_id      INT,
    detection_layer TEXT,        -- 'snort' | 'isolation_forest' | 'scan_persistent'
    anomaly_score   REAL,        -- NULL for signature-based alerts
    notified      BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (sid, cid)
);

CREATE TABLE IF NOT EXISTS signature (
    sig_id       SERIAL PRIMARY KEY,
    sig_name     TEXT,
    sig_class_id INT,
    sig_priority INT,
    sig_rev      INT,
    sig_sid      INT UNIQUE
);

-- PostgreSQL NOTIFY trigger for n8n real-time alerting
CREATE OR REPLACE FUNCTION notify_new_event()
RETURNS TRIGGER AS $$
BEGIN
  PERFORM pg_notify('new_event', row_to_json(NEW)::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER event_insert_trigger
AFTER INSERT ON event
FOR EACH ROW EXECUTE FUNCTION notify_new_event();
```

---

## Environment Variables

| Variable           | Description              | Default  |
| ------------------ | ------------------------ | -------- |
| `DB_NAME`          | PostgreSQL database name | `mpu_db` |
| `DB_USER`          | PostgreSQL username      | `mpu`    |
| `DB_PASSWORD`      | PostgreSQL user password | `123`    |
| `DB_ROOT_PASSWORD` | PostgreSQL root password | `root`   |

> Credentials are intentionally simple as per university project requirements.

---

## API Endpoints

All endpoints are reachable through Nginx under `/api/`.

| Method | Endpoint                 | Description                               |
| ------ | ------------------------ | ------------------------------------------ |
| POST   | `/api/alerts/ingest`     | Unified ingest for Snort and ML alerts     |
| GET    | `/api/alerts/snort`      | Latest alerts (default: 50)                |
| GET    | `/api/stats/summary`     | Total alert count and breakdown            |
| GET    | `/api/stats/by-protocol` | Alert count grouped by protocol            |
| GET    | `/api/stats/by-priority` | Alert count grouped by priority            |
| GET    | `/api/stats/timeline`    | Alert count per hour (last 24 hours)       |
| GET    | `/api/docs`              | Auto-generated API documentation           |

---

## Telegram Alerting with n8n

n8n connects to PostgreSQL and listens on the `new_event` notification channel. Whenever any detection layer — Snort, the exfiltration model, or the scan_persistent model — inserts a row into the `event` table, the PostgreSQL trigger fires a `NOTIFY` call, and n8n immediately delivers a formatted message to the configured Telegram bot — no polling involved.

The workflow:

```
Postgres Trigger (channel: new_event)
        --> Code node (formats alert message)
        --> Telegram node (sends to bot)
```

Sample message:

```
NIDS Alert
Layer: isolation_forest
Type: Anomalous Flow (Exfiltration)
Anomaly Score: -0.1923
Src IP: 10.10.10.3
Dst IP: 10.10.10.1
Ports: 51422 -> 22
Time: 2026-09-05 14:12:07
```

n8n's editor is accessible through Nginx at `http://localhost/n8n/`. Workflow state is persisted in `./n8n_data` so workflows survive container restarts.

---

## Testing & Validation

### Threshold validation

A controlled timeline test combined normal traffic with labeled attack scenarios — 5MB/10MB/100MB/200MB downloads and uploads, slow scans (5s/10s), a ping sweep, a TCP+UDP scan, and a null scan — plotted as anomaly score vs. time. Normal-traffic points consistently scored above `-0.10`, while every exfiltration and port-scan point scored below it, confirming `-0.10` as a clean decision boundary for both models.

### Exfiltration model — bulk transfer (post-fix)

Three sequential `curl` bulk downloads from Kali against the server (`file_100mb.bin` ×2, `file_200mb.bin`) produced 3 `per_flow_anomaly` alerts, scores `-0.1923`, `-0.2012`, `-0.1986` — each well below threshold, batching 2–6 flows and ~100–600MB per alert.

### Exfiltration model — SSH/SCP upload (encrypted traffic)

A 50MB file uploaded from Kali to the server twice via SCP produced two correctly flagged `per_flow_anomaly` alerts (scores `-0.1850` and `-0.1845`), despite SSH/SCP traffic never appearing in the training baseline — demonstrating detection from flow metadata alone, which matters because SSH payloads are encrypted.

### Scan_persistent model — slow port scan

A `bash /dev/tcp` loop probing 12 ports with a 5-second delay between each, run twice, produced two `window_anomaly` alerts (19 flows / 11 distinct ports over 60s each, scores `-0.1709` and `-0.1706`) — correctly caught by the windowed model; the per-flow model wasn't expected to catch single low-rate probes individually.

### Scan_persistent model — connection-rate flood

100 rapid connection attempts to a single open port with no delay produced one `window_anomaly` alert (100 flows / 1 distinct port, score `-0.1633`) — confirming the model is sensitive to connection rate independent of port diversity.

### Snort cross-comparison

Snort correctly matched the connection-rate flood against an existing DoS rule, but did **not** detect the slow port scan, the bulk-transfer exfiltration test, or the SSH/SCP exfiltration test — the exact gap the ML layers are designed to close.

### Consolidated view

The closing evidence for the testing section is a single "Detection Timeline with Attack Regions" chart — anomaly score vs. time with the `-0.10` threshold line, exfiltration points in orange and port-scan points in red — covering every scenario above plus the ping sweep, null scan, and TCP+UDP scan, showing normal traffic staying above the line while every attack type stays below it.

---

## Known Limitations

- **Scan non-detection edge cases:** extremely slow/low-rate scans near the window boundary may not consistently trigger `window_anomaly`.
- **Idle connection testing:** long-lived idle connections (as opposed to persistent-but-active ones) haven't been exhaustively tested against the scan_persistent model.
- **East-West detection:** an Isolation Forest model for east-west (lateral movement) traffic was explored but never implemented; a different approach is planned for a future iteration rather than being part of the current system.
- A dashboard-polling traffic artifact (port 80) produced a borderline `per_flow_anomaly`-like score (`-0.105`) during one connection-rate-flood test run, flagged as a possible test-methodology false positive rather than a true detection.

---

## Security Notes

- Snort runs with `privileged: true` and `network_mode: host` — required for raw packet capture
- Nginx is the only service exposed on the host beyond what's needed for development; all other internal services are reached only through the reverse proxy
- PostgreSQL port 5432 is exposed on the host for development convenience only; restrict it in production
- `.env` is excluded from version control via `.gitignore`
- WebGoat is deliberately vulnerable — never expose it on a public or production network
- Run this system on an isolated lab network only

---

## Roadmap

**Completed**

- [x] Snort 3 containerized with host network access
- [x] alerts_watcher forwarding Snort alerts to the backend via HTTP ingest
- [x] Isolation Forest exfiltration model (25 per-flow features, threshold `-0.10`)
- [x] Isolation Forest scan_persistent model (10 windowed per-src-IP features)
- [x] Unified `ml_detector.py` running both models in parallel threads
- [x] Fixed detection-layer independence bug (per-flow model now runs unconditionally)
- [x] FastAPI backend with unified alert ingest and stats endpoints
- [x] React dashboard with live data refresh, port/service mapping, priority filters
- [x] Nginx reverse proxy routing to frontend, backend, and n8n
- [x] WebGoat as attack simulation target
- [x] Real-time Telegram alerting via n8n and PostgreSQL NOTIFY
- [x] Threshold validation via controlled timeline testing
- [x] Layer-by-layer testing: exfiltration (bulk transfer, SSH/SCP), scan (slow scan, connection flood), Snort cross-comparison

**Planned**

- [ ] East-West (lateral movement) detection layer, using an alternative approach
- [ ] Broader idle-connection and edge-case scan testing

---

## Authors

- **Jad** — [GitHub profile link]
- **Abdulkader Motraji** — [GitHub profile link]

Manara Private University — Computer Engineering, Final-Year Graduation Project

---

## License

This project is licensed under the MIT License.
