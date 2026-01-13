# SOC-Event-Monitor

A lightweight **SOC monitoring prototype** that simulates authentication event collection, SSH-style brute-force detection, alert correlation, and SOC-style reporting.

This project is designed to demonstrate **Security Operations Center (SOC)** fundamentals, log analysis, and detection logic aligned with real-world SIEM pipelines.

---

## 🔍 Project Overview

SOC-Event-Monitor ingests authentication logs from multiple sources, normalizes them into a common event schema, applies rule-based detection logic, and generates structured alerts and summaries.

It is inspired by real SOC workflows and aligns with common **SSH brute-force detection use cases**.

---

## 🧱 Architecture

```
Raw Logs
  ├── Generic auth logs
  └── SSH auth.log
        ↓
[ Parsers ]
        ↓
[ Normalizer ]  →  Unified SOC event schema
        ↓
[ Detection Engine ]
        ↓
[ Structured Alerts + SOC Summary ]
```

---

## 📁 Project Structure

```
SOC-Event-Monitor/
│
├── main.py            # Pipeline orchestration & detection logic
├── alerts.py          # Structured alert model & output
├── normalizer.py      # SIEM-style event normalization
├── ssh_parser.py      # SSH auth.log parser
├── sample_logs.txt    # Generic authentication logs
├── ssh_auth.log       # Sample SSH authentication logs
├── alerts.json        # Generated alerts (runtime output)
└── .gitignore
```

---

## 🚨 Detection Capabilities

### ✅ Implemented Rules

* **IP-based brute-force detection**

  * Multiple authentication failures from the same IP within a time window

* **Success-after-brute-force escalation**

  * Successful login following repeated failures from the same IP

* **Suspicious IP detection**

  * Alerts on authentication attempts from known suspicious IPs

* **Alert deduplication**

  * Prevents alert flooding by correlating events per IP

---

## 📊 SOC Summary Output

At runtime, the system produces:

* Total authentication events
* Successful vs failed logins
* Top attacking IPs
* Targeted users per IP

This mirrors the **initial triage view** used by Tier-1 SOC analysts.

---

## 📄 Alert Output Format

Alerts are generated as **structured JSON**, suitable for SIEM ingestion:

```json
{
  "severity": "HIGH",
  "attack_type": "BRUTE_FORCE",
  "source_ip": "192.168.1.10",
  "username": "admin",
  "attempts": 5,
  "time_window": {
    "start": "2026-01-13T10:00:01",
    "end": "2026-01-13T10:04:10"
  }
}
```

---

## ▶️ How to Run

```bash
python main.py
```

The script will:

* Parse generic and SSH logs
* Normalize events
* Apply detection rules
* Print alerts and SOC summary
* Generate `alerts.json`

---

## 🎯 Learning Objectives

This project demonstrates:

* SOC-oriented thinking and workflows
* Log parsing and normalization
* Rule-based detection logic
* Alert correlation and suppression
* Python data processing for cybersecurity

---

## 🚀 Future Improvements

* Web dashboard (Flask)
* Configurable rules (YAML/JSON)
* Real-time log ingestion
* MITRE ATT&CK mapping
* SIEM export formats (CEF, CSV)

---

