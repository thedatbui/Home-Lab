# 07 — Control Mapping: NIST CSF 2.0, ISO/IEC 27001:2022, NIST SP 800-53 Rev. 5
 
## Purpose and scope
 
This document maps the controls of the lab (OPNsense, Nginx, Flask app, Wazuh, CI pipeline) to three frameworks, **with evidence and an honest status**. It is a self-assessment of a training environment, not a certification claim.
 
**Status legend**
 
| Status | Meaning |
|---|---|
| ✅ Implemented | Control exists and is evidenced in this repository |
| 🟡 Partial | Exists but incomplete, or documented only in the README/CV |
| ❌ Gap | Not implemented in the lab (often on purpose, as the app is vulnerable) |
 
---
 
## 1. NIST CSF 2.0
 
| Function / Category | Lab control | Evidence | Status |
|---|---|---|---|
| **GV** Govern | No security policy or risk register for the lab | — | ❌ Gap |
| **ID.AM** Asset management | Architecture diagram lists hosts, zones and IPs | README (Architecture) | ✅ |
| **ID.RA** Risk assessment | Vulnerability/mitigation table, STRIDE threat model | README, `docs/08-stride-threat-model.md` | ✅ |
| **PR.AA** Identity, authentication, access | Role check on admin routes; but MD5 hashes, hardcoded admin, no MFA, unauthenticated `/all-users` | `app.py`, `schema.sql` | 🟡 / ❌ (intentional) |
| **PR.DS** Data security | Honeyfile; no TLS on the public leg (HTTP/80), MD5 at rest | README, `app.py` | ❌ Gap |
| **PR.PS** Platform security | Nginx header hardening and rate limiting; Flask debug mode on | README (config not in repo), `app.py` | 🟡 |
| **PR.IR** Infrastructure resilience | OPNsense segmentation (WAN→DMZ→LAN), default-deny LAN→WAN | README (Network Defenses) | ✅ |
| **DE.CM** Continuous monitoring | Wazuh agents on all hosts, FIM on uploads, auditd on honeyfile, Nginx and app log ingestion | README (Detection), `docs/03`, `docs/05` | ✅ (rules not in repo) |
| **DE.AE** Adverse event analysis | Detection table per kill-chain step; documented blind spot (cron persistence not alerted) | README, `docs/05` | ✅ |
| **RS** Respond | Attacks were *simulated*, but there is no incident response procedure, playbook or containment test | — | ❌ Gap |
| **RC** Recover | No backup or restore test | — | ❌ Gap |
 
> Correction to my own earlier suggestion: the attack simulation tests **detection** (DE), it is not the **Respond** function. Respond needs a documented procedure (see next steps).
 
---
 
## 2. ISO/IEC 27001:2022, Annex A (technological controls)
 
| Control | Lab control | Evidence | Status |
|---|---|---|---|
| **A.5.15** Access control | Role-based check (`customer`/`admin`) on admin routes | `app.py` | 🟡 |
| **A.5.24–A.5.27** Incident management and learning | Findings and takeaways documented per phase, no formal process | README (Key takeaways) | 🟡 |
| **A.8.2** Privileged access rights | Hardcoded admin account; admin can create admins | `schema.sql` | ❌ (intentional) |
| **A.8.5** Secure authentication | MD5, no lockout, no MFA | `app.py` | ❌ (intentional) |
| **A.8.8** Management of technical vulnerabilities | SAST/SCA in CI, reports as artifacts | `main.yml` | ✅ |
| **A.8.9** Configuration management | Debug mode, hardcoded key; Nginx/OPNsense configs not versioned | `app.py` | ❌ / 🟡 |
| **A.8.15** Logging | Login success/failure, admin access, user creation with IP, written to `/var/log/myapp/app.log` | `app.py` | ✅ (missing: reviews, uploads, log integrity) |
| **A.8.16** Monitoring activities | Wazuh SIEM, FIM, honeyfile, custom Nginx rule (>50 404s/min) | README (Detection) | ✅ |
| **A.8.20** Network security | OPNsense zones and rules | README (Network Defenses) | ✅ |
| **A.8.22** Segregation of networks | DMZ / LAN / WAN separation, attacker confined to DMZ port 80 | README (Architecture) | ✅ |
| **A.8.24** Use of cryptography | No TLS on the public leg, MD5 for passwords | `app.py`, README | ❌ Gap |
| **A.8.25** Secure development life cycle | CI pipeline with SAST/SCA/secrets scan | `main.yml` | ✅ |
| **A.8.28** Secure coding | Insecure patterns on purpose, with secure alternatives left as comments in the code | `app.py` | 🟡 |
| **A.8.29** Security testing | SAST (Bandit, Semgrep), pentest following the kill chain, DAST described on the CV (add evidence) | CI, `docs/01–05` | ✅ / 🟡 |
 
---
 
## 3. NIST SP 800-53 Rev. 5 (selected controls)
 
| Control | Lab control | Evidence | Status |
|---|---|---|---|
| **AU-2 / AU-12** Event logging, audit generation | Application logs and auditd rules | `app.py`, `docs/05` | ✅ |
| **AU-6** Audit review, analysis, reporting | Wazuh correlation and alerts | README | ✅ |
| **SI-4** System monitoring | Wazuh agents on every host | README | ✅ |
| **SI-7** Software and information integrity | FIM on `/var/www/uploads/` detected the webshell upload | `docs/03` | ✅ |
| **SC-7** Boundary protection | OPNsense DMZ/LAN, DNAT, default-deny | README | ✅ |
| **SC-5** Denial-of-service protection | Nginx `limit_req` (20 r/min) | README | 🟡 |
| **SC-8** Transmission confidentiality | HTTP only on the public leg | README | ❌ Gap |
| **IA-5** Authenticator management | MD5, default admin | `app.py`, `schema.sql` | ❌ (intentional) |
| **AC-3 / AC-6** Access enforcement, least privilege | Role checks duplicated per route; `/all-users` unprotected; www-data used by the webshell | `app.py` | 🟡 |
| **SI-10** Information input validation | `|safe` on reviews, upload validated by extension only | templates, `docs/03` | ❌ (intentional) |
| **RA-5** Vulnerability monitoring and scanning | Bandit, Semgrep, Dependency-Check | `main.yml` | ✅ |
| **SA-11** Developer testing and evaluation | CI scans on every push/PR | `main.yml` | ✅ |
| **CM-6** Configuration settings | Hardened Nginx headers (config not published) | — | 🟡 |
| **IR-4** Incident handling | Not documented | — | ❌ Gap |
 