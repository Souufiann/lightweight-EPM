# 🛡️ DevSecOps Enterprise EDR & Network Telemetry System

An enterprise-ready, high-performance hybrid Host-based Intrusion Detection and Prevention System (HIDS/IPS). This platform applies modern DevSecOps principles by isolating resource-heavy analytical tasks into a containerized cluster while maintaining an agile, low-overhead native security agent on the protected endpoint.

The architecture combines **local edge heuristics** (Expert-System Engine) for rapid pre-filtering, **cryptographic process verification**, and a **centralized microservices server** offering real-time telemetry streaming, aggregated persistence caching, and deep threat observability.

---

## ✨ System Features & Performance Engineering

* **Containerized Decoupled Backend:** Built on an asynchronous Python/Flask engine running within a sandboxed container deployment (`Docker` and `Docker Compose`). Instantly scalable and fully OS-agnostic.
* **Edge-AI Heuristic Scoring:** The client agent dynamically evaluates executable behaviors locally based on multi-vector risks (directory execution paths, unstandardized communication ports, binary digital trust status, and Living-off-the-Land impersonation metrics).
* **Zero-Trust Communication:** Telemetry pipelines are strictly locked down using cryptographic Bearer Token validation headers (`AGENT_SECRET_KEY`) to prevent adversarial log injection or telemetry spoofing.
* **Stateful Signature Caching:** Reduces high-overhead native subshell calls by tracking approved Authenticode footprints locally via a persistent, on-disk registry (`signature_cache.json`). Validations seamlessly survive endpoint reboots.
* **Indexed Logging Layer:** Employs an optimized structural index on the storage database timestamp layers. Graph aggregation pipelines run consistently at fast lookup speeds rather than scaling linearly as log history builds up.
* **Active Intrusion Prevention:** Interfaces directly with low-level kernel space monitoring and invokes dynamic PowerShell command chains to configure immediate, 1-click **Windows Defender Firewall Outbound Blocking Rules** when anomalies hit threshold critical metrics.
* **Observability Matrix:** Displays real-time streaming line charts via `Chart.js` tracking Safe vs. Dangerous connection vectors across the network alongside a live data feed of active incident logs.

---

## 🏗️ Architecture Design Spec

### 1. Central Management Core (The Dockerized Server)
* Orchestrates global intelligence routing and incoming payload parsing.
* Manages `threat_cache.db` (SQLite3 with active indexing) to isolate storage layers away from unprivileged host environments.
* Proxies downstream external connections to third-party Cloud Threat Intelligence Providers (AbuseIPDB V2 REST API), caching malicious IP scores globally to stay within tight rate limits.

### 2. Monitoring Probe (The Windows Native Agent)
* Executes via low-overhead system mapping libraries (`psutil`) tracking live connection bindings.
* Executes isolated system subshells silently via background creation flags (`0x08000000`) to query binary digital security states.
* Invokes responsive, thread-safe local graphical interfaces (`tkinter`) and push alert systems (`plyer`) to minimize latency during critical remediation windows.

---

## 🚀 Quick Deployment Blueprint

### Part 1: Central Server Infrastructure (DevOps Deployment)

**Prerequisites:** Docker and Docker Compose configured on your deployment platform (Ubuntu/Debian server recommended, though macOS/Windows hosts are completely supported).

1. Clone or copy the deployment directory onto the machine:
   ```bash
   cd server/