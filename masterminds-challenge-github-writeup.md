# Masterminds — TryHackMe Challenge Write-Up

> **Platform:** TryHackMe · **Category:** Network Forensics / Malicious Traffic Analysis · **Type:** Challenge · **Tool:** Brim (Zui) · **Status:** ✅ Completed

---

## Table of Contents

- [Scenario](#scenario)
- [Artifacts Provided](#artifacts-provided)
- [Investigation Methodology](#investigation-methodology)
- [Machine 1 — Emotet Infection](#machine-1--emotet-infection)
- [Machine 2 — Redline Stealer + Phorphiex Worm](#machine-2--redline-stealer--phorphiex-worm)
- [Machine 3 — C2 Infrastructure](#machine-3--c2-infrastructure)
- [Brim Filters Used](#brim-filters-reference)
- [IOC Summary](#ioc-summary)
- [Key Findings](#key-findings)
- [Challenges](#challenges)
- [Key Learnings](#key-learnings)
- [Real-World Application](#real-world-application)
- [Next Steps](#next-steps)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [References](#references)

---

## Scenario

**Victims:** Three machines from the Finance department  
**Suspected initial access:** Phishing attempt and indexed USB drive  
**Objective:** Analyze malicious network traffic from three infected PCAPs to identify the threat actors, malware families, C2 infrastructure, and full scope of the compromise across all three machines.

---

## Artifacts Provided

| File | Coverage |
|------|----------|
| PCAP 1 | Machine 1 — Finance department workstation |
| PCAP 2 | Machine 2 — Finance department workstation |
| PCAP 3 | Machine 3 — Finance department workstation |

Each PCAP captured the full network traffic from one compromised endpoint — allowing independent investigation of each machine's infection chain before correlating findings across all three.

---

## Investigation Methodology

**Tool:** Brim (Zui)

Each PCAP was loaded individually and investigated in sequence — starting from Machine 1 and progressing through all three. The anchor for each investigation was the **victim IP address**, used as the primary filter to isolate traffic specific to that machine before expanding the analysis.

Core investigation sequence per machine:
1. Identify victim IP from HTTP traffic
2. Review HTTP connections — status codes, URIs, response bodies
3. Review DNS queries — unique requests, query counts, suspicious domains
4. Review alerts — Suricata/network IDS detections
5. Identify downloaded files and C2 domains
6. Confirm malware identity via VirusTotal / URLhaus

---

## Brim Filters Reference

```bash
# All HTTP connections — key fields
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri, status_code

# DNS queries sorted by frequency
_path=="dns" | count() by query | sort -r

# Suricata/IDS alerts by source and destination IP
event_type=="alert" | alerts := union(alert.category) by src_ip, dest_ip

# Unique connections — deduplicate by IP and port
cut id.orig_h, id.resp_p, id.resp_h | sort | uniq
```

---

## Machine 1 — Emotet Infection

**Victim IP:** `192.168.75.249`

### Step 1 — HTTP Connection Analysis

```bash
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri, status_code
```

**Finding 1 — Reconnaissance with failed connections:**
The victim IP made connections to 2 suspicious domains that returned **HTTP 404** responses — indicating the attacker's infrastructure may have been probing for available resources or the C2 endpoints were temporarily unavailable.

> **Analyst note:** Repeated 404 responses from the same external IP before a successful connection is a behavioral pattern worth flagging. It can indicate C2 beacon attempts cycling through dead endpoints before finding an active one.

**Finding 2 — Successful payload delivery:**
The victim made a successful HTTP connection to `199.59.242.153` and received a response with a body length of **1309 bytes** — indicating content was delivered to the machine.

**Finding 3 — File download:**

| Field | Value |
|-------|-------|
| URI contacted | `bhaktivrind[.]com/cgi-bin/JBbb8/` |
| File downloaded | `catzx.exe` |
| Malicious IP | `185.239.243.112` |

**VirusTotal lookup → Malware identified: Emotet**

### Step 2 — DNS Analysis

```bash
_path=="dns" | count() by query | sort -r
```

**Finding:** A unique DNS request was made to `cab[.]myfkn[.]com` with a query count of **7** — repeated DNS lookups to a single suspicious domain is consistent with C2 beaconing behavior.

### Machine 1 — Summary

| IOC | Value |
|-----|-------|
| Victim IP | `192.168.75.249` |
| C2 domain | `bhaktivrind[.]com` |
| C2 IP | `185.239.243.112` |
| DNS beacon domain | `cab[.]myfkn[.]com` |
| Malware downloaded | `catzx.exe` |
| Malware family | **Emotet** |
| Secondary C2 IP | `199.59.242.153` |

---

## Machine 2 — Redline Stealer + Phorphiex Worm

**Victim IP:** `192.168.75.146`

### Step 1 — HTTP POST Analysis

```bash
_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri, status_code
```

**Finding 1 — Data exfiltration via POST:**
The victim IP made **3 POST connections** to `5.181.156.252` — HTTP POST requests from an infected machine to an external IP are a strong indicator of data being sent outbound to attacker infrastructure.

**Finding 2 — Binary download:**

| Field | Value |
|-------|-------|
| Download domain | `hypercustom[.]top` |
| Full URI | `hypercustom[.]top/jollion/apines.exe` |
| Host IP | `45.95.203.28` |

**URLhaus lookup → Stealer identified: Redline Stealer**

### Step 2 — IDS Alert Analysis

```bash
event_type=="alert" | alerts := union(alert.category) by src_ip, dest_ip
```

**Finding:** Suricata alert fired:

| Field | Value |
|-------|-------|
| Alert type | **Network Trojan Detected** |
| Source IP | `192.168.75.146` (victim) |
| Destination IP | `45.95.203.28` (attacker) |

### Step 3 — C2 Domain and Worm Identification

Three C2 domains were identified from which additional binaries were downloaded:

| C2 Domain | IP Address |
|-----------|------------|
| `efhoahegue[.]ru` | `162.217.98.146` |
| `afhoahegue[.]ru` | `199.21.76.77` |
| `xfhoahegue[.]ru` | `63.251.106.25` |

**Additional findings:**

| Detail | Value |
|--------|-------|
| DNS queries to first C2 IP | 2 |
| Total binaries downloaded | 5 |
| User-Agent used | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0` |
| Total DNS connections | 986 |
| Worm family identified | **Phorphiex** |

> **Analyst note:** A spoofed macOS Firefox user-agent on a Windows Finance machine is immediately suspicious — the user-agent string does not match the expected endpoint profile. Attackers use spoofed user-agents to blend malicious traffic with legitimate browser activity and evade basic user-agent filtering.

> **Phorphiex** (also known as Trik) is a worm known for distributing other malware families — including Emotet and ransomware — via spam campaigns and USB propagation. Its presence alongside Emotet on a Finance department network is consistent with a multi-stage infection chain.

### Machine 2 — Summary

| IOC | Value |
|-----|-------|
| Victim IP | `192.168.75.146` |
| POST C2 IP | `5.181.156.252` |
| Download domain | `hypercustom[.]top` |
| Download IP | `45.95.203.28` |
| C2 domains | `efhoahegue[.]ru`, `afhoahegue[.]ru`, `xfhoahegue[.]ru` |
| C2 IPs | `162.217.98.146`, `199.21.76.77`, `63.251.106.25` |
| Stealer | **Redline Stealer** |
| Worm | **Phorphiex** |
| Binaries downloaded | 5 |
| Total DNS connections | 986 |

---

## Machine 3 — C2 Infrastructure

Findings from the third PCAP were correlated with infrastructure identified across Machines 1 and 2, completing the full picture of the attacker's network footprint across all three compromised Finance department endpoints.

---

## IOC Summary — All Three Machines

| IOC Type | Value |
|----------|-------|
| Victim IPs | `192.168.75.249`, `192.168.75.146` |
| Emotet download domain | `bhaktivrind[.]com` |
| Emotet C2 IP | `185.239.243.112` |
| Emotet payload | `catzx.exe` |
| DNS beacon | `cab[.]myfkn[.]com` (7 queries) |
| Secondary IP | `199.59.242.153` |
| Redline download domain | `hypercustom[.]top` |
| Redline download URI | `/jollion/apines.exe` |
| Redline host IP | `45.95.203.28` |
| POST exfil IP | `5.181.156.252` |
| Phorphiex C2 — 1 | `efhoahegue[.]ru` — `162.217.98.146` |
| Phorphiex C2 — 2 | `afhoahegue[.]ru` — `199.21.76.77` |
| Phorphiex C2 — 3 | `xfhoahegue[.]ru` — `63.251.106.25` |
| Spoofed User-Agent | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0` |
| Malware families | **Emotet**, **Redline Stealer**, **Phorphiex** |

---

## Key Findings

| Finding | Detail |
|---------|--------|
| Three Finance machines compromised | Each with distinct but related malware infections |
| Emotet identified on Machine 1 | Downloaded via `bhaktivrind[.]com` — confirmed via VirusTotal |
| Redline Stealer on Machine 2 | Downloaded via `hypercustom[.]top` — confirmed via URLhaus |
| Phorphiex worm on Machine 2 | 3 C2 domains, 5 binaries downloaded, 986 DNS connections |
| HTTP POST data exfiltration | 3 outbound POST connections to `5.181.156.252` |
| Suricata alert fired | Network Trojan Detected — `192.168.75.146` → `45.95.203.28` |
| Spoofed user-agent | macOS Firefox string on Windows Finance endpoint |
| DNS beaconing | 7 queries to `cab[.]myfkn[.]com` from Machine 1 |

---

## Challenges

**Challenge:** Understanding which traffic patterns were significant versus routine background noise in a large PCAP.

**Resolution:** Applied the core principle built across previous investigations — lead with a known anchor (victim IP), use targeted filters to isolate relevant traffic, and let repeated patterns (repeated 404s before a 200, repeated DNS queries to the same domain, high DNS connection counts) surface the attacker activity. Prior experience with Brim from Boogeyman 1 made the filter syntax second nature, allowing focus to shift from tool mechanics to investigative thinking.

---

## Key Learnings

1. **Repeated 404s before a 200 from the same external IP is a behavioral red flag.** It suggests C2 beacon attempts cycling through endpoints until one responds — a pattern worth alerting on in a production SIEM.

2. **Every alert deserves attention — even when traffic looks routine.** The Suricata Network Trojan alert on Machine 2 was the clearest confirmation signal in that investigation. IDS alerts exist to be investigated, not ignored.

3. **Spoofed user-agents are a detection signal, not a bypass.** A macOS Firefox user-agent on a Windows Finance workstation is immediately inconsistent. Knowing what user-agents are normal for an environment makes anomalies visible.

4. **Domain naming patterns reveal infrastructure relationships.** `efhoahegue[.]ru`, `afhoahegue[.]ru`, and `xfhoahegue[.]ru` — three domains with nearly identical naming, registered on the same infrastructure. Attacker-generated domain names often follow patterns that reveal they belong to the same campaign.

5. **Tool familiarity compounds across investigations.** Having used Brim in Boogeyman 1, this challenge required no time spent learning the tool — only applying it. Every investigation builds the platform for the next one to move faster and go deeper.

---

## Real-World Application

Multi-machine compromises involving Emotet, Redline Stealer, and Phorphiex represent a real and actively documented threat pattern. Emotet in particular has been observed as a loader that delivers secondary payloads — including stealers and ransomware — to compromised machines in finance and healthcare sectors.

The analysis workflow used here — isolating each machine's PCAP, anchoring to victim IP, filtering HTTP and DNS traffic, correlating IDS alerts, and confirming malware identity via threat intelligence platforms — mirrors exactly how a SOC analyst or network forensics specialist would approach a multi-endpoint compromise investigation.

The ability to work across three PCAPs simultaneously, correlate C2 infrastructure, and identify three distinct malware families from network traffic alone demonstrates practical, production-ready network forensics skills.

---

## Next Steps

- [ ] Research Emotet's full infection chain — how it persists, propagates, and delivers secondary payloads
- [ ] Study Phorphiex/Trik in depth — its USB propagation mechanism and spam distribution model
- [ ] Practice building SIEM detection rules for the behavioral patterns identified here (repeated 404 → 200, high DNS counts, POST exfiltration)
- [ ] Explore URLhaus and Abuse.ch as standard threat intelligence resources for malware URL lookups
- [ ] Practice multi-PCAP correlation — building a unified timeline across multiple infected machines

---

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Phishing: Spearphishing Attachment | T1566.001 |
| Replication Through Removable Media (USB) | T1091 |
| Ingress Tool Transfer (binary downloads) | T1105 |
| Application Layer Protocol: Web (HTTP C2) | T1071.001 |
| DNS C2 / Beaconing | T1071.004 |
| Exfiltration Over C2 Channel (POST) | T1041 |
| Masquerading: Spoofed User-Agent | T1036 |
| Automated Exfiltration (Redline Stealer) | T1020 |

---

## References

- [Emotet — CISA Advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-280a)
- [Redline Stealer — URLhaus](https://urlhaus.abuse.ch/)
- [Phorphiex/Trik — MITRE ATT&CK](https://attack.mitre.org/software/S0158/)
- [Brim / Zui Documentation](https://www.brimdata.io/docs/)
- [VirusTotal](https://www.virustotal.com)
- [URLhaus — Abuse.ch](https://urlhaus.abuse.ch/)

---

*Linus Yohanna | Actively exploring the cyber space and building threat intelligence, one layer at a time.*
