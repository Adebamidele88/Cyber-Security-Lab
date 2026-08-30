# Network Traffic Analysis — Incident Report

**Analyst:** Adebamidele Segun
**Classification:** Internal / Portfolio Demonstration
**Tooling:** Wireshark, tcpdump, HTB Academy lab environment

## Executive Summary

This report documents a packet-capture-based investigation into suspicious network activity originating from internal host **172.16.10.2**. The investigation was initiated after a Security Manager confirmed that a user on this host had been exfiltrating data via image files. A follow-up live capture was requested to determine whether additional malicious activity was occurring.

Analysis of the resulting traffic identified three independent, corroborating indicators of compromise:

1. **Recurring anonymous FTP transfers** of a file named `flag.jpeg`, repeating at a consistent ~180-second interval.
2. **Beaconing-style TCP connections** to a non-standard, high-risk port (**4444**) on a secondary internal host, consistent with Command-and-Control (C2) check-in behavior.
3. **Cleartext credential exposure** during an HTTP POST to an internal web application's login form, revealing the compromised user's identity.

A related, earlier case study (a separate capture, `Wireshark-lab-2.pcap`) is included as an appendix, documenting an analogous image-based exfiltration technique used to smuggle a nested `.pcap` file and multiple JPEGs out via a plaintext HTTP file server.

## Scope & Methodology

**In scope:**
- Host `172.16.10.2` (primary suspect)
- Host `172.16.10.20` (internal web/FTP server)
- Host `172.16.10.90` (secondary host, suspected C2 endpoint)

**Methodology:**
- Statistical triage using Wireshark's **Conversations** and **Protocol Hierarchy** windows to identify anomalous traffic volume, duration, and protocol usage before inspecting individual packets.
- Targeted **display filters** (`ftp`, `ftp-data`, `tcp.port == 4444`, `http.request`, `nbns`, `browser`) to isolate specific conversations of interest.
- **TCP/HTTP stream reconstruction** (Follow Stream, in Raw mode where binary data was involved) to recover file contents and readable payloads.
- **Object extraction** via `File → Export Objects` for FTP-DATA and HTTP transfers.
- **Expert Information** review to rule out packet loss / retransmission as an explanation for anomalous connection behavior.

## Timeline of Findings

| Time (relative) | Event |
|---|---|
| T+0s | Capture begins; baseline ARP/IGMP/mDNS housekeeping traffic observed (benign) |
| ~T+122s | First anonymous FTP session: login → `RETR flag.jpeg` |
| ~T+147s | Web application enumeration begins: sequential GET requests to `register.php`, `forgot_password.php`, `admin.php`, `index.php`, `logout.php` |
| ~T+147s | `POST /login.php` submitted in cleartext — credentials captured |
| ~T+301s | Second anonymous FTP session, identical command sequence, `RETR flag.jpeg` repeated |
| Throughout | Multiple short TCP connections to `172.16.10.90:4444`, recurring at irregular but repeated intervals |
| ~T+481s, ~T+661s | Third and fourth repeats of the FTP login/RETR sequence, confirming a ~180s interval pattern |

## Detailed Findings

### Finding 1 — Recurring Anonymous FTP Exfiltration/Beacon (`flag.jpeg`)

**Observed behavior:**
USER anonymous
SYST
PWD
TYPE I
SIZE flag.jpeg
PASV
RETR flag.jpeg

This exact seven-step command sequence was observed **four separate times** across the capture, at approximately 180-second intervals (122s, 301s, 481s, 661s). Each session authenticated with the `anonymous` account — no credentials required — and pulled the same file, `flag.jpeg`, from `172.16.10.20`.

**Assessment:** The regular, scripted interval strongly suggests automated tooling rather than manual user activity. This is consistent with either:
- A scheduled exfiltration/persistence mechanism disguised as routine file access, or
- A file-based "dead drop" style beacon, using an innocuous-looking anonymous FTP pull as cover traffic.

The use of **anonymous authentication** on the FTP service is itself a configuration weakness independent of the malicious activity — it permits unauthenticated access to file contents by any host on the network.

**Evidence:** FTP control channel (`ftp.request.command`), FTP-DATA transfer objects (extracted via Export Objects), Protocol Hierarchy (`FTP Data`: 9.3% of packets, 89% of capture bytes — confirming this was the dominant payload in the capture).


### Finding 2 — Beaconing to Non-Standard Port 4444

**Observed behavior:**

Multiple short-lived TCP connections were identified between `172.16.10.2` and `172.16.10.90` on **TCP port 4444**:

| Metric | Observation |
|---|---|
| Port | 4444 (no registered/standard service) |
| Packet count per connection | 2–5 packets |
| Byte count per connection | 134–462 bytes |
| Number of distinct connections observed | 5+ across the capture |

**Assessment:** Port 4444 is not associated with any standard service and is widely recognized as the **default listener port for Metasploit's `reverse_tcp` payload**, a common penetration-testing/attacker post-exploitation framework. The small, repeated, near-identical connection footprint is consistent with a compromised host performing periodic **C2 check-in ("beaconing")** — confirming liveness or reachability to a listener rather than transferring substantive data on each check-in.

**Evidence:** `tcp.port == 4444` filter results; Statistics → Conversations (TCP tab) showing repeated stream entries between the same host pair.

### Finding 3 — Cleartext Credential Exposure

**Observed behavior:**

An HTTP `POST /login.php` request to `172.16.10.20` was submitted with the following multipart form data, in plaintext (no TLS):

uname: bob
psw:   B0b_hardw0rker!


**Assessment:** The internal web application does not use HTTPS, meaning authentication credentials are transmitted in fully readable cleartext and are trivially recoverable by any party capturing traffic on the same network segment. This finding also **identifies the compromised employee** as the user "bob," directly linking the account to host `172.16.10.2`.

**Server details (from HTTP response headers):**

Server: Apache/2.4.41 (Ubuntu)

**Evidence:** `http.request` filter; Follow HTTP Stream on the `POST /login.php` transaction (stream 3).


### Finding 4 — Automated Web Application Enumeration

**Observed behavior:**

Immediately surrounding the credential submission, `172.16.10.2` issued a rapid, sequential series of `GET` requests to distinct application endpoints:

```
GET /register.php
GET /forgot_password.php
GET /admin.php
GET /index.php
GET /logout.php


Each request-response cycle completed in a fraction of a second, with a new TCP connection opened for nearly every request (rapidly incrementing ephemeral source ports), rather than reusing an existing connection.

**Assessment:** This pattern — new connection per page, minimal delay between requests, sequential coverage of authentication-adjacent endpoints — is inconsistent with normal human browsing behavior and consistent with **automated endpoint enumeration or reconnaissance**, typically performed to map an application's attack surface prior to (or following) exploitation.

**Evidence:** `http.request` filter; TCP Conversations tab showing dozens of short-duration streams between `172.16.10.2` and `172.16.10.20`.


## Indicators of Compromise (IOCs)

| Type | Value | Notes |
|---|---|---|
| Internal IP (compromised host) | `172.16.10.2` | Source of all suspicious activity |
| Internal IP (file/web server) | `172.16.10.20` | Apache/2.4.41 (Ubuntu); hosts FTP + web app |
| Internal IP (suspected C2) | `172.16.10.90` | Hostname: `NTA-RDP-SRV01`; listener on TCP/4444 |
| Port | `4444/tcp` | Non-standard; common reverse-shell listener port |
| Filename | `flag.jpeg` | Repeatedly retrieved via anonymous FTP |
| Compromised credential | `bob` / `B0b_hardw0rker!` | Transmitted in cleartext HTTP |


## Impact Assessment

- **Confidentiality:** High. Credentials for an active employee account were exposed in cleartext and are trivially recoverable by any on-path observer. Data (image-based content) was confirmed exfiltrated in a related capture.
- **Integrity:** Undetermined from network evidence alone; no direct evidence of data modification was observed in this capture.
- **Availability:** No impact observed.
- **Likely attack stage:** Based on the combination of findings (recurring low-volume file pulls, C2-style beaconing, and application enumeration), the affected host shows indicators consistent with an established foothold performing reconnaissance and low-and-slow exfiltration, rather than an initial-access or noisy smash-and-grab attack.


## Recommendations

1. **Isolate and forensically image** host `172.16.10.2` for offline analysis; do not rely solely on network evidence.
2. **Rotate credentials** for the "bob" account immediately, and audit all activity performed under it.
3. **Block outbound traffic to `172.16.10.90:4444`** at the host and network firewall level pending investigation of that host's role.
4. **Enforce HTTPS/TLS** on the internal web application to prevent further cleartext credential exposure.
5. **Disable anonymous FTP access** on `172.16.10.20`, or replace FTP entirely with an authenticated, encrypted transfer method (SFTP/FTPS).
6. **Deploy connection-interval monitoring / beacon detection** on the network to catch similar low-volume, regularly-timed C2 patterns earlier in future incidents.


## Appendix A — Wireshark Filters Used

| Filter | Purpose |
|---|---|
| `ip.addr == 172.16.10.2` | Baseline scoping to the suspect host |
| `ftp` / `ftp.request.command` | Isolate FTP control-channel commands |
| `ftp-data` | Isolate raw file transfer contents |
| `tcp.port == 4444` | Investigate the suspected C2 port |
| `http.request` | Enumerate all HTTP requests made |
| `nbns` / `browser` | Attempt hostname resolution via NetBIOS/Windows Browser Protocol |
| `tcp.analysis.retransmission` | Rule out packet loss as a cause of anomalous connection behavior |

## Appendix B — Related Case Study: Image-Based Exfiltration (Separate Capture)

A separate, earlier capture (`Wireshark-lab-2.pcap`) demonstrated a related exfiltration technique from host `192.168.159.129` to `10.10.20.129`, hosted on a lightweight Python `SimpleHTTP` server rather than Apache:

- **Protocol Hierarchy analysis** revealed a JPEG object (`395,248 bytes`) accounting for **43.2% of the entire capture's byte volume** despite representing only 3 packets — a strong size-to-count anomaly indicating the file was disproportionately large for its apparent purpose.
- Multiple JPEGs (`htb.jpeg`, `Rise-Up.jpg`, `water.jpg`) were transferred via plain HTTP, alongside a **nested packet capture file** (`http_with_jpegs.cap`, `Content-Type: application/vnd.tcpdump.pcap`) — indicating a "capture within a capture" exfiltration technique.
- Two additional TCP streams (17 and 18) to the same server showed a complete three-way handshake followed by a **6.4-second idle period with zero payload exchanged**, before a clean four-way close — a pattern inconsistent with normal browsing and consistent with a connectivity/reachability check.

This case study reinforces the broader pattern observed in the primary investigation: attackers in this environment favor **plaintext protocols and innocuous-looking file types** (images, routine file transfers) as cover for exfiltration and C2 activity.



*This report was produced as part of hands-on packet analysis training using Wireshark and HTB Academy lab environments. All IP addresses and credentials referenced are internal to isolated lab environments and hold no external significance.*
