# 01 — Reconnaissance

## Objective

Identify the exposed services and discover the application's public and administrative routes from the attacker network.

## Commands

Run these commands from the Kali attacker machine:

```bash
nmap -sV -p 80 10.10.10.1

ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
     -u http://10.10.10.1/FUZZ \
     -mc 200,301,302,403
```

## Execution and expected result

The scan should reveal the HTTP service exposed through OPNsense. Directory enumeration may reveal routes such as the login page, administrative pages, and upload functionality. The results are useful even when a route returns `403`: a forbidden response confirms that the path exists and that access control is being enforced at a later layer.

![](images/recons-nmap.png)
The Nmap screenshot shows the attacker scanning `10.10.10.1`. The host is reachable, but the 999 other tested TCP ports are filtered. Only `80/tcp` is reported as open and identified as HTTP. This is consistent with the architecture: OPNsense publishes the reverse proxy on WAN port 80 and does not expose the Flask application or the LAN directly. `-sV` also asks Nmap to identify the service, rather than merely reporting that the port accepts connections.

![](images/recons-ffuf.png)
The ffuf screenshot shows two content-discovery passes. The first one targets the web root and finds:
- `/admin`, `/login`, `/register`, `/logout`, `/uploads` (root level)
The second pass targets `/admin/FUZZ` and finds:
- `/admin/uploads` and `/admin/create_user` (admin panel)

The wordlist is sent as the value of `FUZZ`, so ffuf replaces that marker with each candidate path. The status matcher (`-mc 200,301,302,403`) keeps successful pages, redirects, and forbidden pages; this is why administrative paths can be reported even when they require authentication. Directory discovery does not exploit a vulnerability by itself, but it reduces the attacker's uncertainty and exposes the routes used by the next stages of the lab.

## Wazuh view

```json
{
  "rule.description": "Multiple pfSense firewall blocks events from same source.",
  "rule.mitre.technique": "Brute Force (T1110)",
  "rule.level": 10,
  "data.srcip": "10.10.10.10",
  "data.dstip": "1.1.1.1",
  "timestamp": "2026-10-14T15:54:05.253Z"
}
```
Note: This is not the full JSON log; only the fields relevant to the demonstration are shown.
![](images/recons-ffuf-wazuh2.png)

The Wazuh screenshot shows the reverse-proxy access logs grouped by `data.id: 404`. It contains 124,555 `GET` requests from `10.10.10.10`, including requests such as `/admin/zkhh` and `/admin/wythe`, which are typical generated candidates from a fuzzing wordlist. A high volume of unknown paths is a useful behavioral indicator: a normal user usually requests a small number of known resources, whereas a content-discovery tool produces many different paths and mostly receives `404`.

The alert also shows rule `31101` (HTTP 400/404 events) and a custom Wazuh correlation for repeated firewall blocks. The `404` count is evidence of reconnaissance, not proof that the firewall has already blocked the scan. This distinction matters: the reverse proxy can log an HTTP request only after the connection has reached it.

## Mitigation

The reconnaissance should be slowed down at two different layers. The firewall protects the network edge by limiting new TCP connections, while Nginx protects the HTTP service by limiting requests. They complement each other but do not measure exactly the same thing.

### Limit rate in `OPNSENSE` (Firewall):
OPNsense provides a `Max new connections` state limit on the matching firewall rule. In the screenshot, the values are `30` connections during `1` second. This is a connection limit, not a precise HTTP requests-per-second limit: one TCP connection can carry several HTTP requests when keep-alive is used, and a single page load can open more than one connection. The limit is therefore most useful against scanners that repeatedly create connections, SYN floods, or clients that do not reuse connections.

![](/docs/images/limit-rate-opn.png)
![](/docs/images/limit-opn-proof.png)

The second screenshot is the observed effect from the attacker side: ffuf is progressing very slowly (about `2 req/sec`) and reports connection errors. This demonstrates that the edge control is interfering with the scan instead of allowing the original burst of requests to reach Nginx. It should not be interpreted as proof that every HTTP request is being rejected: the exact result depends on connection reuse, the firewall rule scope, and whether the client is receiving a TCP reset or a timeout.

### Limit rate in `Nginx` (Reverse Proxy)

Nginx can enforce a true HTTP request rate per client address:

```nginx
# Allow an average of 10 requests per second per source address.
limit_req_zone $binary_remote_addr zone=anti_fuzz:10m rate=10r/s;

# Return Too Many Requests when the limit is exceeded.
limit_req_status 429;
```

The zone stores a compact counter for each client IP. The `burst` value allows a short queue above the average rate; `nodelay` does not intentionally delay those requests, so requests that exceed the available burst are rejected immediately with HTTP `429`.

```nginx
limit_req zone=anti_fuzz burst=20 nodelay;
```

With this example, a client can make a short burst of up to 20 requests, but sustained traffic is kept around 10 requests per second. The `429` response is important because it gives monitoring a reliable application-layer signal and prevents the scanner from confusing throttling with an ordinary missing page.

Wazuh can then turn repeated `429` responses from the reverse proxy into an alert:

```
<rule id="100429" level="10" frequency="10" timeframe="5">
    <if_matched_sid>31101</if_matched_sid>
    <id>429</id>
    <same_srcip />
    <description>Fuzzing Attack: rate limit reached by $(srcip)</description>
    <mitre>
      <id>T1110</id>
      <id>T1595</id>
    </mitre>
    <group>web,attack,rate_limit,</group>
  </rule>
```

The rule raises an alert when the same source generates at least 10 matching events in 5 seconds. In practice, the base rule or decoder must also extract the HTTP status as `id: 429`; otherwise the correlation rule will not match. The MITRE mappings describe the behavior as brute-force/automated discovery (`T1110`) and network service scanning (`T1595`).

```
 <active-response>
    <command>firewall-drop</command>
    <rules_id>100429</rules_id>
    <location>defined-agent</location>
    <agent_id>002</agent_id>
    <timeout>600</timeout>
  </active-response>
```
Wazuh can also respond to that fuzzing discovery by banning the Ip for 600 seconds.
### Why the layered mitigation works

The controls stop the scan at progressively more informed layers:

1. **OPNsense** limits the rate at which new network connections can reach the published service. This reduces the amount of scanning traffic that enters the DMZ and protects the reverse proxy from connection bursts.
2. **Nginx** sees the client IP and the HTTP request path, so it can apply a per-client request budget even when connections are reused. Excess requests receive `429` instead of being forwarded to Flask.
3. **Wazuh** uses the resulting firewall events, `404` bursts, and `429` responses as detection signals. It provides visibility and alerting; it does not replace the preventive controls.
