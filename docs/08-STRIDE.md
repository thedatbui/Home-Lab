# 08 — STRIDE Threat Model of the Lab
 
## Scope
 
Architecture from the README: attacker on WAN → OPNsense → Nginx reverse proxy (DMZ) → Flask app + SQLite (LAN), monitored by Wazuh agents reporting to a Wazuh manager (LAN). An admin user manages the shop through the browser and uploads images to a separate `upload.php` endpoint.
 
Threats come from reading `app.py`, `schema.sql`, the templates and `docs/01–06`. Items marked *(to verify)* depend on a configuration that is not published in the repository.
 
## Data flow diagram
 
```
 [Attacker / Customer]          [Admin browser]
          │ DF1 HTTP :80              │ DF4 HTTP :80 (upload form)
══════════╪════════ Trust boundary 1: WAN | DMZ ═══════════════
          ▼                           ▼
   ┌─────────────┐             ┌──────────────┐
   │ OPNsense    │────────────►│ Nginx (DMZ)  │
   └─────────────┘             └───┬──────┬───┘
                        DF2 :5000  │      │ DF4 :80  (/upload.php, /uploads/)
══════════ Trust boundary 2: DMZ | LAN ═════╪══════╪════════════
                                   ▼      ▼
                ┌────────────────────────────────────────┐
                │ LAN VM  192.168.1.2  (same host)       │
                │  Flask app            :5000  ──DF3──► SQLite
                │  Web server + PHP-FPM :80   ──────► /var/www/html/uploads
                │  Wazuh agent (FIM, auditd, app logs)   │
                └───────────────────┬────────────────────┘
                                    │ DF5 logs / FIM / auditd
                                    ▼
                           Wazuh manager (LAN)
```
 
## Assets
 
| Asset | Why it matters |
|---|---|
| Admin session and admin role | Full control of the shop and of the upload feature |
| User table (hashes) | Credentials of all users |
| Flask `SECRET_KEY` | Allows forging session cookies |
| Backend server (LAN) | Pivot point to the Wazuh manager |
| Logs and Wazuh alerts | Evidence and detection capability |
 
## Rating method
 
**Likelihood (L)** and **Impact (I)** from 1 (low) to 3 (high), **Risk = L × I** (1–9). These are my own estimates for a lab; adjust them to your judgement.
**Status:** *Exploited* (demonstrated in the lab), *Open* (present in the code), *Mitigated*, or *To verify*.
 
## Threats
 
| ID | STRIDE | Threat | Where (evidence) | L | I | Risk | Status | Mitigation |
|---|---|---|---|---|---|---|---|---|
| S1 | Spoofing | Forge a Flask session cookie to impersonate `admin` | `SECRET_KEY="dev"` in `app.py` | 3 | 3 | **9** | Open | Secret from environment, rotate, short sessions |
| S2 | Spoofing | Log in as admin with the known default account and crack MD5 hashes | `schema.sql`, MD5 in `app.py` | 3 | 3 | **9** | Open | bcrypt/Argon2, no default credentials, MFA, lockout |
| S3 | Spoofing | Spoof client IP in logs through `X-Forwarded-For` | `ProxyFix(x_for=1)` | 1 | 2 | 2 | To verify | Nginx must overwrite the header with `$remote_addr` |
| T1 | Tampering | Stored XSS in reviews forges an admin action (no CSRF token) | `|safe` in templates | 3 | 3 | **9** | **Exploited** | Autoescaping, CSP, Flask-WTF CSRF, SameSite cookies |
| T2 | Tampering | Upload a webshell: only the extension is checked | `upload.php`, `docs/03` | 3 | 3 | **9** | **Exploited** | Extension and MIME allowlist, store outside webroot, no script execution on the upload path |
| T3 | Tampering | Modify app files or the database after getting a shell | `docs/04–05` | 2 | 3 | 6 | Partial | FIM detects new files in uploads; extend FIM to the app directory |
| T4 | Tampering | Open redirect through the `next` parameter | `login()` in `app.py` | 2 | 2 | 4 | Open | Accept relative paths only |
| T5 | Tampering | Debug mode exposes the Werkzeug console to anyone who can reach port 5000 through the proxy | `app.run(debug=True, host="0.0.0.0")` | 2 | 3 | 6 | To verify | Production server (Gunicorn), debug off, block `/console` |
| R1 | Repudiation | An attacker with shell access edits local logs | `/var/log/myapp/app.log` on the same host | 2 | 2 | 4 | Mitigated | Wazuh forwards events in near real time; also forward logs off-host |
| R2 | Repudiation | Reviews and uploads are not logged, so actions can't be attributed | `product()` has no log call | 2 | 2 | 4 | Open | Log author, IP and action for every state-changing route |
| I1 | Information disclosure | Anyone can dump all users and hashes without logging in | `/all-users` has no authentication | 3 | 3 | **9** | Open | Require admin, return only needed fields, never hashes |
| I2 | Information disclosure | Password hash printed to stdout at each login | `print(...)` in `login()` | 2 | 2 | 4 | Open | Remove, never log secrets |
| I3 | Information disclosure | Sessions and credentials travel in clear text on the public leg | HTTP/80 only | 2 | 3 | 6 | Open | TLS on Nginx, HSTS, secure cookie flags |
| I4 | Information disclosure | User enumeration through sequential ids | `/users/<id>` | 2 | 1 | 2 | Open | Ownership check, opaque identifiers |
| D1 | Denial of service | Directory fuzzing floods the app | `docs/01` | 2 | 2 | 4 | Mitigated | `limit_req` 20 r/min; Wazuh rule on >50 404s/min |
| D2 | Denial of service | Flask development server and SQLite used in the serving path | `app.run`, SQLite | 2 | 2 | 4 | Open | Gunicorn behind Nginx, a real database if load grows |
| D3 | Denial of service | Single Wazuh manager: if it fails, detection stops | README | 1 | 3 | 3 | Open | Monitor the manager, alert on missing agent heartbeats |
| E1 | Elevation of privilege | From `www-data` shell to the backend and then the LAN | `docs/04` | 2 | 3 | 6 | Mitigated | OPNsense blocks LAN→WAN and attacker→Wazuh; least-privilege service account |
| E2 | Elevation of privilege | CSRF chain creates a new admin account | `/admin/createUser`, `docs/02` | 3 | 3 | **9** | **Exploited** | CSRF tokens, re-authentication for admin actions |
| E3 | Elevation of privilege | `shell=True` could become command injection if the dictionary lookup is changed | `/admin/diagnostics` | 1 | 3 | 3 | Latent | Argument list, no shell |
| E4 | Elevation of privilege | Admin check copied into each route, easy to forget on a new route | `/all-users` shows the failure | 2 | 3 | 6 | Open | Central decorator (`@admin_required`) |
 
## Reading the results
 
- **Six risks score 9** (S1, S2, T1, T2, I1, E2). Four of them chain into the demonstrated attack: XSS → forged admin creation → upload → shell. Breaking **any single link** (CSRF token, upload validation, escaping) stops the chain, which is the main takeaway of the lab.
- **Detection coverage** (see README): upload and honeyfile access are detected; SQL-type and logic flaws such as I1 and E4 are invisible to the SIEM and need SAST or code review.
- **Residual risk** after the proposed mitigations would drop to 2–3 for most rows; the remaining ones are S3 and T5, which depend on configuration to verify