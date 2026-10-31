# TryHackMe – Zeek Exercises

**Date Completed**: October 2026  
**Platform**: TryHackMe  
**Category**: Network Analysis / Threat Hunting / SOC  
**Difficulty**: Intermediate  

## Scenario Overview

The goal of this room was to investigate a series of network traffic captures and detect malicious activity under different scenarios using **Zeek** (formerly Bro).  

The exercises focused on analysing Zeek-generated logs to identify anomalous behaviour, phishing attempts, and exploitation activity.

## Tools Used

- **Zeek** – Primary network analysis framework
- **VirusTotal** – Hash-based malware confirmation
- **CyberChef** – Decoding encoded payloads (Base64)

## Analysis Methodology

### 1. Anomalous DNS Activity

Loaded the DNS tunneling PCAP and generated logs:

```bash
zeek -Cr dns-tunneling.pcap
```

**Key Investigations:**

- Counted the number of IPv6 (AAAA) records:
  ```bash
  cat dns.log | grep 'AAAA' | wc -l
  ```

- Found the longest connection duration:
  ```bash
  cat conn.log | zeek-cut duration | sort -n
  ```

- Counted unique domain queries (excluding known legitimate domain):
  ```bash
  cat dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | rev | sort -u | grep -v 'cisco-update.com' | wc -l
  ```

- Identified the source host IP:
  ```bash
  cat conn.log | zeek-cut id.orig_h | uniq
  ```

### 2. Phishing Attempt

Analysed HTTP and file activity related to a phishing campaign.

- Identified the source IP:
  ```bash
  cat conn.log | zeek-cut id.orig_h
  ```

- Investigated the domain and URI of the malicious download:
  ```bash
  cat http.log | zeek-cut method host uri
  ```

- Extracted file hashes from `files.log`:
  ```bash
  cat files.log | zeek-cut md5
  ```

The extracted MD5 hashes (malicious document and .exe) were submitted to VirusTotal for confirmation. The contacted domain was also validated.

### 3. Log4j Exploitation Attempt

Loaded the provided PCAP with the Zeek script and analysed the following:

- Counted signature hits in `signatures.log` using `grep`.
- Identified the scanning tool via User-Agent:
  ```bash
  cat http.log | zeek-cut user_agent
  ```

- Examined requested URIs and extensions:
  ```bash
  cat http.log | zeek-cut uri
  ```

- Extracted Base64-encoded values from the traffic and decoded them using **CyberChef**.

## Key Findings Summary

| Scenario              | Key Activity Detected                          | Primary Logs Used          |
|-----------------------|------------------------------------------------|----------------------------|
| Anomalous DNS         | DNS tunneling indicators, unusual AAAA records | dns.log, conn.log          |
| Phishing Attempt      | Malicious file download + associated domain    | http.log, files.log, conn.log |
| Log4j Exploitation    | Signature hits, scanning tool, encoded payloads| signatures.log, http.log   |

## Challenges Encountered

The main difficulty was selecting the correct Zeek log fields and filters. Understanding exactly what the question was asking for significantly improved the efficiency of the investigation.

## Lessons Learned & Takeaways

1. Clearly understanding the problem/situation is critical before diving into logs.
2. Zeek logs (`dns.log`, `http.log`, `files.log`, `conn.log`, `signatures.log`) provide powerful visibility when queried correctly.
3. Combining Zeek with external tools (VirusTotal + CyberChef) strengthens analysis confidence.
4. Knowing common attack patterns (DNS tunneling, phishing delivery, Log4j) helps you know what to look for.

## Skills Demonstrated

- Zeek log analysis and command-line investigation
- Detection of DNS tunneling and anomalous DNS behaviour
- Phishing traffic analysis and malware hash extraction
- Log4j exploitation detection
- Use of `zeek-cut`, filtering, and log correlation
- Base64 decoding with CyberChef
- Structured threat hunting documentation

---

**This write-up demonstrates practical Zeek-based network analysis and threat hunting skills relevant to SOC and Blue Team roles.**
```

