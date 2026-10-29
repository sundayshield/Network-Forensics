# TryHackMe – Carnage Challenge

**Date Completed**: October 2026  
**Platform**: TryHackMe  
**Category**: Network Forensics / Malware Traffic Analysis / SOC Level 1–2  
**Difficulty**: Intermediate  

## Scenario Overview

Eric Fischer from the Purchasing Department at Bartell Ltd received an email from a known contact containing a Word document attachment. After opening the document and enabling content, the endpoint protection agent immediately alerted on suspicious outbound connections from his workstation.

A PCAP was captured from the network sensor and provided for analysis. The goal was to reconstruct the full attack chain, identify the malware, track secondary payloads, detect Cobalt Strike C2 activity, and document post-infection behaviour.

## Tools Used

- **Wireshark** – Deep packet inspection, stream following, and custom filters
- **Brim (Zeek-based)** – High-level query-driven analysis and rapid IOC extraction
- **VirusTotal** – Hash-based malware confirmation

## Analysis Methodology

### 1. Initial Access & Payload Delivery

Started analysis in **Wireshark** with the filter:

```
http.request.method == "GET"
```

Followed the relevant TCP streams to identify the download of a ZIP archive containing a malicious file.

Switched to **Brim** and used the built-in **File Activity** queries to extract the hash of the downloaded ZIP without opening it. The hash was submitted to VirusTotal, confirming the file as malicious.

### 2. Secondary Payload Downloads

Used the Wireshark filter:

```
tls.handshake.extensions_server_name
```

to uncover additional domains involved in secondary downloads. One of the domains presented an SSL certificate issued by GoDaddy.

### 3. Cobalt Strike C2 Detection

Identified Cobalt Strike beaconing by observing high-frequency HTTP requests.

- In **Brim**: Used HTTP request queries and examined headers.
- In **Wireshark**: Reviewed Statistics → IPv4 Conversations to surface the most active external IPs, then validated them on VirusTotal.

Two Cobalt Strike C2 IP addresses were confirmed.

### 4. Post-Infection Activity

- **IP Geolocation / External IP Check**  
  Filter used:

  ```
  dns.qry.name == "api.ipify.org"
  ```

  The malware queried this API to determine the victim’s public IP address.

- **Malicious Spam Campaign**  
  Filter used:

  ```
  smtp.req.command == "MAIL"
  ```

  Revealed outbound spam activity after successful infection.

- **HTTP POST Traffic**  
  Brim HTTP POST queries + Wireshark filter:

  ```
  http.request.method == "POST"
  ```

  (followed by TCP stream analysis) exposed additional post-infection command-and-control communications.

## Key Findings Summary

| Stage              | Description                                      | Key Indicators / Techniques                  |
|--------------------|--------------------------------------------------|----------------------------------------------|
| Initial Access     | Malicious Word document → ZIP download           | HTTP GET, File hash on VirusTotal            |
| Secondary Payloads | Multiple domain downloads                        | TLS SNI, GoDaddy certificate                 |
| C2                 | Cobalt Strike beacons                            | High-frequency HTTP, 2 external IPs          |
| Reconnaissance     | Victim IP discovery                              | api.ipify.org DNS query                      |
| Post-Infection     | Malicious spam + additional C2                   | SMTP MAIL commands, HTTP POSTs               |

## Tool Comparison

- **Brim**: Extremely efficient thanks to pre-built queries (File Activity, HTTP Requests, HTTP POSTs). Ideal for rapid triage and IOC extraction.
- **Wireshark**: Superior for detailed packet-level investigation, following streams, and understanding exact protocol behaviour.

Both tools complement each other perfectly when solid filtering skills are applied.

## Challenges Encountered

- Translating attack concepts into effective filters (especially TLS SNI and post-infection patterns).
- Mentally mapping the full attack flow before selecting the optimal next filter.
- Interpreting less common traffic patterns and understanding what certain protocol fields represent in a real incident context.

## Lessons Learned & Takeaways

1. Always begin by clearly identifying internal vs external IP addresses.
2. Every discovered piece of traffic is a stepping stone to the next intelligence.
3. Strong filter knowledge (both Wireshark display filters and Brim/Zeek queries) dramatically accelerates analysis.
4. Combining high-level (Brim) and low-level (Wireshark) tools produces the most complete picture.
5. Documenting the reasoning behind each filter choice is as valuable as the IOCs themselves for future investigations.

## Skills Demonstrated

- Network traffic analysis & PCAP investigation
- Malware delivery chain reconstruction
- Cobalt Strike C2 detection
- IOC extraction and VirusTotal validation
- Advanced Wireshark filtering
- Brim/Zeek query usage
- Post-infection behaviour analysis (spam, external IP checks)
- Structured SOC-style documentation

---

**This write-up serves as practical proof of hands-on network forensics and blue-team analysis capabilities.**
```

---

### How to Import into GitHub

1. Go to your repository (or create a new one, e.g. `cybersecurity-portfolio` or `TryHackMe-Carnage`).
2. Click **Add file** → **Create new file**.
3. Name it exactly: `README.md`
4. Copy the entire content from the file above and paste it.
5. Commit the changes.

Alternatively, download the file below and upload it directly.