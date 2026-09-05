# Incident Report: RDP Credential Compromise Leading to Reverse Shell Access

**Analyst:** Adebamidele88
**Case Reference:** NTA-RDP-01
**Evidence Files:** `guided-rdp.pcapng`, `guided-analysis.pcap`
**Tools Used:** Wireshark (TLS decryption, Follow TCP Stream, Conversations, I/O Graphs, Protocol Hierarchy Statistics)


## 1. Executive Summary

Analysis of two related packet captures reveals a complete attack chain against host **10.129.43.29** (`NTA-RDP-SRV01`), beginning with a Remote Desktop Protocol (RDP) logon using weak, guessable credentials and culminating in an interactive reverse shell session used to create a persistent backdoor administrator account. The two captures, when read together, tell a single incident story: an attacker authenticated to the host over RDP, worked hands-on-keyboard for approximately 90 seconds, and then pivoted to a secondary command-and-control (C2) channel on TCP port 4444 to perform reconnaissance and establish persistence.


## 2. Scope and Objective

| Item | Detail |
|---|---|
| Issue reported | Suspicious traffic involving internal host 10.129.43.4 / 10.129.43.29 |
| Time window | Traffic captured within the relevant 48-hour incident window |
| Target scope | 10.129.43.27, 10.129.43.29, and 10.129.43.4, and any hosts connecting to them |
| Protocols in scope | RDP/TLS (port 3389), unidentified TCP service (port 4444) |
| Evidence | `guided-rdp.pcapng` (RDP session capture), `guided-analysis.pcap` (port 4444 session capture) |


## 3. Timeline of Events

| Stage | Source | Destination | Port | Description |
|---|---|---|---|---|
| 1 | 10.129.43.27 | 10.129.43.29 | 3389 | Initial RDP connection attempt (TCP stream 0); TLS handshake begins, session reset (RST) after ~6 seconds |
| 2 | 10.129.43.27 | 10.129.43.29 | 3389 | Second RDP connection (TCP stream 1) established ~8.8 seconds later; authenticates successfully and runs for ~98.85 seconds |
| 3 | 10.129.43.29 | 10.129.43.4 | 4444 | Outbound reverse-shell connection established (TCP stream 0 in `guided-analysis.pcap`), active from the start of that capture through its full ~51.3 second duration |


## 4. Findings: RDP Access and Credential Compromise

### 4.1 Connection Overview
Two TCP conversations were identified on port 3389 between 10.129.43.27 (client) and 10.129.43.29 (server):

- **Stream 0** — 15 packets, ~3 kB, duration 6.27s. TLS handshake completed (Client Hello, Server Hello/Certificate, Key Exchange, Application Data), then terminated by a RST from the client side. Consistent with a failed or aborted initial connection attempt.
- **Stream 1** — 2,210 packets, ~205 kB, duration 98.85s. This is the substantive session and the focus of this analysis.

### 4.2 RDP Negotiation
The initial RDP negotiation request (pre-TLS) carried the connection cookie:

Cookie: mstshash=bucky

This is consistent with the client-supplied username used for connection routing prior to authentication.

### 4.3 Credential Disclosure via TLS Decryption
TLS decryption keys were loaded into Wireshark (`Preferences → Protocol → TLS → RSA Keys List`), enabling inspection of the encrypted RDP handshake. The decrypted **ClientInfo PDU** (packet 51) revealed the logon credentials in cleartext at the RDP protocol layer:

| Field | Value |
|---|---|
| Domain | *(blank — local account)* |
| Username | `bucky` |
| Password | `Welcome1` |

**Assessment:** the password follows a common weak-password pattern (capitalized dictionary word + single trailing digit), consistent with either a default/unrotated credential or a password easily obtained via brute force, credential stuffing, or password-spraying against a small wordlist.

### 4.4 Session Behavior Analysis
An I/O graph of stream 1 (packets/second over time) shows an irregular, bursty traffic pattern: multiple high-activity spikes (up to ~90 packets/sec) separated by low-activity troughs, including one sustained ~20-second idle period. This pattern — variable burst height, non-repeating rhythm, and a genuine idle gap — is consistent with **live, interactive, hands-on-keyboard use** rather than an automated script, which would typically produce either a uniform, repeating cadence or one continuous burst with no natural pauses.

**Conclusion:** the RDP session represents an attacker actively operating the compromised host interactively for approximately 90 seconds following logon as `bucky`.


## 5. Findings: Reverse Shell and Post-Exploitation Activity

A separate capture (`guided-analysis.pcap`) recorded a TCP session originating from the same host, **10.129.43.29**, outbound to **10.129.43.4 on port 4444** — a port with no standard service assignment but commonly associated with Metasploit's `multi/handler` and generic reverse-shell listeners.

### 5.1 Session Details
- **10.129.43.29:50612 → 10.129.43.4:4444**
- 35 packets, ~4 kB, spanning the entire capture duration (~51.3s), beginning at Rel Start 0.000215 (i.e., already in progress at the start of the capture)

### 5.2 Reconstructed Shell Session
Following the TCP stream reconstructed an interactive `cmd.exe` session with the following commands executed, in order:

1. `whoami` → `NTA-RDP-SRV01\mrb3n`
2. `ipconfig` → confirmed host IP 10.129.43.29, default gateway 10.129.0.1
3. `cd c:\` → `dir` → enumerated root of the C: drive
4. `net user hacker Passw0rd1 /add` → created a new local user account, `hacker`
5. `net localgroup administrators hacker /add` → added the `hacker` account to the local Administrators group


## 6. Combined Attack Narrative

1. **Initial Access** — Attacker authenticates to 10.129.43.29 over RDP as `bucky`, using the weak password `Welcome1`. An earlier connection attempt (stream 0) failed or was aborted before this successful logon.
2. **Interactive Access** — Attacker operates the host hands-on-keyboard for ~90 seconds via the RDP session.
3. **Secondary Channel Established** — A reverse shell connection is opened from 10.129.43.29 outbound to attacker infrastructure at 10.129.43.4:4444, providing a command-line channel independent of the RDP session.
4. **Discovery** — Attacker runs `whoami`, `ipconfig`, and `dir` to confirm host identity, network context, and file system layout.
5. **Persistence** — Attacker creates a new local account `hacker` with password `Passw0rd1` and adds it to the local Administrators group, ensuring continued privileged access independent of the `bucky` credentials or the reverse-shell channel remaining active.


## 7. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Compromised host | 10.129.43.29 (`NTA-RDP-SRV01`) |
| Compromised RDP credential | `bucky` / `Welcome1` |
| Local user context in shell | `mrb3n` |
| Attacker-controlled listener | 10.129.43.4:4444 |
| Persistence account created | `hacker` / `Passw0rd1` (local Administrators) |
| Suspicious port | TCP/4444 (common Metasploit/reverse-shell default) |


## 8. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Valid Accounts | T1078 | RDP logon using disclosed credentials (`bucky`) |
| Brute Force (suspected) | T1110 | Weak, guessable password pattern; failed connection attempt preceding successful logon |
| Remote Services: RDP | T1021.001 | RDP used as the initial access vector |
| Command and Scripting Interpreter | T1059 | Interactive `cmd.exe` session over reverse shell |
| System Information Discovery | T1082 | `whoami`, `ipconfig` |
| File and Directory Discovery | T1083 | `dir` |
| Create Account: Local Account | T1136.001 | `net user hacker Passw0rd1 /add` |
| Account Manipulation | T1098 | `net localgroup administrators hacker /add` |
| Application Layer Protocol (suspected) | T1071.001 | Traffic to non-standard port 4444; protocol not confirmed beyond plaintext shell |


## 9. Impact Assessment

- Host 10.129.43.29 is confirmed compromised with administrator-level access.
- Two independent means of regaining access now exist: the original `bucky` RDP credentials and the newly created `hacker` local administrator account.
- The discrepancy between the RDP logon identity (`bucky`) and the shell session identity (`mrb3n`) is unresolved and should be treated as a possible indicator of a broader compromise (e.g., stolen session, additional valid credentials, or lateral movement within the host).
- No evidence of data exfiltration or lateral movement to other hosts was identified in either capture; this remains unconfirmed rather than ruled out, pending live traffic capture and endpoint review.


## 10. Recommendations

1. **Immediately disable/remove** the `hacker` local account on `NTA-RDP-SRV01` (10.129.43.29).
2. **Reset credentials** for the `bucky` and `mrb3n` accounts, and review both accounts' recent authentication and activity history.
3. **Isolate** 10.129.43.29 from the network pending full forensic review.
4. **Block** outbound/inbound traffic to 10.129.43.4:4444 at the firewall as an interim containment measure.
5. **Enforce strong password policy and MFA** on all RDP-exposed accounts; `Welcome1`-style passwords should be rejected by policy.
6. **Restrict RDP exposure** — place RDP behind a VPN or Remote Desktop Gateway rather than exposing 3389 directly, and consider Network Level Authentication (NLA) enforcement.
7. **Review Windows Event Logs** on the host (Security Event IDs 4624/4625 for logons, 4720/4732 for account creation and group membership changes) to corroborate this timeline and identify how `mrb3n`'s context was reached.
8. **Deploy live traffic capture** on the 10.129.43.0/24 segment to confirm whether the port 4444 channel or the `hacker` account are still being used to access the environment.
9. **Sweep other hosts** on 10.129.43.0/24 for the same `hacker` account or connections to 10.129.43.4:4444, in case this is not an isolated incident.


## 11. Analyst Notes

- TLS decryption of the RDP session was made possible by an available RSA/session key file; in a real-world engagement without server-side key access, credential disclosure at this layer would not be observable from network capture alone, underscoring the value of endpoint-side logging as a complementary data source.
- The `T1071.001` mapping is marked as suspected rather than confirmed, since payload analysis of the port 4444 session was limited to the plaintext shell content visible in the stream; no protocol-specific headers (e.g., Meterpreter framing) were positively identified.
