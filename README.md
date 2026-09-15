# SMTP Email Traffic Forensics — Forensic Findings Summary

**Lab:** SBT-DF203 LAB-4 | **Author:** Ibrahim Diseh Garba | **Date:** 12 September 2026

---

## Executive Summary

This document summarizes the key forensic findings from the analysis of a historical SMTP email capture (`smtp.pcap`, 27 KB, dated 5 October 2009). The capture records a single plaintext SMTP session in which an email was sent from an internal client network to a public mail server. Because no encryption (STARTTLS or SMTPS) was negotiated, the entire SMTP dialogue—including authentication credentials, message headers, and body content—is fully recoverable.

---

## 1. Session Identification

### Timeline
- **Capture Date:** 5 October 2009
- **Session Start:** 01:05:54 UTC-0500 (server timezone)
- **Message Header Date:** Mon, 5 Oct 2009 11:36:07 +0530 (sender timezone = India Standard Time)
- **Capture Duration (SMTP):** ~4.17 seconds (frames 6–56)
- **Protocol Stack:** Ethernet II → IPv4 → TCP → SMTP

### Network Endpoints
| Role | IP Address | Port | MAC Address | Notes |
|------|-----------|------|-------------|-------|
| **Client (Sender)** | 10.10.1.4 | 1470 | 00:e0:1c:3c:17:c2 | Private RFC 1918 address; last-hop MAC is Cradlepoint router |
| **Server (Receiver)** | 74.53.140.153 | 25 | 00:1f:33:d9:81:60 | Public IP (ThePlanet.com datacenter, historical ASN); last-hop MAC is Netgear router |

**Key Observation:**  
The captured MAC addresses are **last-hop router interfaces only**. They do not identify the original email client hardware (NIC) because the capture was taken after Layer-2 routing. To identify the client's hardware, one would need a capture on the client's local network segment.

---

## 2. SMTP Server Identification

### Service-Ready Banner (Frame 6)
```
220 xc90.websitewelcome.com ESMTP Exim 4.69 #1 Mon, 05 Oct 2009 01:05:54 -0500
```

### Server Capabilities (Frame 9)
```
250 xc90.websitewelcome.com Hello GP [122.162.143.157]
SIZE 52428800
PIPELINING
AUTH PLAIN LOGIN
```

### Findings
- **MTA Software:** Exim 4.69 (released 2008, now obsolete)
- **Hostname:** xc90.websitewelcome.com
- **Max Message Size:** 52,428,800 bytes (~50 MB)
- **Authentication Support:** Both AUTH PLAIN and AUTH LOGIN offered
- **Pipelining:** Enabled (allows multiple commands before waiting for responses)

---

## 3. Authentication Exchange

### Mechanism Used
The client chose **AUTH LOGIN**, a challenge-response scheme that sends username and password encoded in Base64.

### Frames and Values

| Frame | Direction | Command/Response | Details |
|-------|-----------|------------------|---------|
| 10 | C → S | AUTH LOGIN | Client initiates authentication |
| 11 | S → C | 334 | Server challenges with Base64("Username:") = `VXNlcm5hbWU6` |
| 12 | C → S | Base64-username | Client sends Base64-encoded username (masked in public report) |
| 13 | S → C | 334 | Server challenges with Base64("Password:") = `UGFzc3dvcmQ6` |
| 14 | C → S | Base64-password | Client sends Base64-encoded password (masked in public report) |
| 15 | S → C | 235 | "Authentication succeeded" — session now authorized |

### Forensic Significance
- Both credentials are transmitted in **plaintext SMTP without encryption**
- Base64 is a **reversible encoding (not encryption)** — full plaintext recovery is trivial
- In contrast, if STARTTLS had been negotiated at any point, the TLS handshake would immediately render all credentials invisible to the analyst
- The absence of a TLS handshake in the packet stream confirms plaintext transmission

### Credentials (Masked for Public Report)
| Field | Public Masked | Protection Note |
|-------|---------------|-----------------|
| Username | gu\*\*\*\*\*\*\*\*@patriots.in | Full value in protected appendix only |
| Password | pu\*\*\*\*\*\*3 | Full value in protected appendix only |

---

## 4. Email Message Details

### Envelope (SMTP Layer)

| Parameter | Value |
|-----------|-------|
| **Sender (MAIL FROM)** | <gurpartap@patriots.in> |
| **Recipient (RCPT TO)** | <raj_deol2002in@yahoo.co.in> |
| **Server Response** | 250 OK id=1Mugho-00003Dg-Un |

### Headers (RFC 5322 Layer)

| Field | Value |
|-------|-------|
| **From** | "Gurpartap Singh" <gurpartap@patriots.in> |
| **To** | <raj_deol2002in@yahoo.co.in> |
| **Subject** | SMTP |
| **Date** | Mon, 5 Oct 2009 11:36:07 +0530 |
| **Message-ID** | <000301ca4581ef9e57f05cedb07d08@in> |
| **MIME-Version** | 1.0 |
| **X-Mailer** | **Microsoft Office Outlook 12.0** |
| **Content-Type** | multipart/mixed (see MIME structure below) |
| **Content-Language** | en-us |
| **Thread-Index** | AcpFgem8bVjJZEDeR1Kh8i+hluyv0a== |

### Message Body (text/plain part)
```
Hello

I send u smtp pcap file
Find the attachment
GPS
```

### MIME Structure
```
multipart/mixed (boundary = "----=_NextPart_000_0004_01CA4580.095693F0")
├── multipart/alternative
│   ├── text/plain         ← main message body (above)
│   └── text/html          ← HTML version of message
└── text/plain (attachment) ← NEWS.txt file
```

### Email Client Identification
**Microsoft Office Outlook 12.0** (Outlook 2007 generation)

**Evidence:**
- X-Mailer header explicitly states version
- Thread-Index value format is characteristic of Exchange/Outlook
- Message-ID domain suffix (@in) is consistent with Microsoft Exchange's local ID format

---

## 5. Timestamp and Timezone Correlation

### Time Zones in This Message
| Component | Timestamp | Timezone | UTC Equivalent |
|-----------|-----------|----------|----------------|
| Server banner (Exim) | 01:05:54 | UTC-0500 | 2009-10-05 06:05:54 UTC |
| Message Date header | 11:36:07 | +0530 (IST) | 2009-10-05 06:06:07 UTC |
| Packet capture | t=0.727 s | (relative) | — |

### Observations
- **IST (India Standard Time, +0530)** is the apparent timezone of the sender
- Email domain `patriots.in` is consistent with India registration
- Server is in central US timezone (UTC-0500)
- All timestamps are internally consistent

---

## 6. Data Transmission Summary

| Metric | Value |
|--------|-------|
| **Total SMTP Frames** | 30 |
| **First SMTP Frame** | Frame 6 (server 220 banner) |
| **Last SMTP Frame** | Frame 56 (server 221 closing) |
| **DATA Fragments** | 14 frames (frames 22–44) |
| **Data Fragment Size** | ~1,452 bytes each |
| **Total Message Bytes** | 15,156 bytes |
| **Capture File Size** | 27,850 bytes (~27 KB) |
| **Data Byte Rate** | 2,920 bytes/second |
| **Data Bit Rate** | 23 kbps |
| **Average Packet Size** | 447.77 bytes |
| **Average Packet Rate** | 6 packets/second |

---

## 7. Encryption Assessment

### STARTTLS Status
```
tshark -r smtp_working.pcap -Y 'smtp.starttls' | wc -l
→ 0 (no STARTTLS command observed)
```

### TLS Handshake Status
```
tshark -r smtp_working.pcap -Y 'tls.handshake.type == 1' | wc -l
→ 0 (no Client Hello observed)
```

### Conclusion
**This session is plaintext SMTP on port 25 with NO encryption negotiation.**

### Evidential Implications

#### What IS Visible in This Capture
- ✅ Server software and version (Exim 4.69)
- ✅ Server hostname and banner
- ✅ SMTP commands and responses (EHLO, AUTH, MAIL FROM, RCPT TO, DATA)
- ✅ Authentication credentials (Base64 username and password)
- ✅ Message envelope (MAIL FROM, RCPT TO addresses)
- ✅ Email headers (From, To, Subject, Date, X-Mailer, Message-ID, etc.)
- ✅ Message body (plain text)
- ✅ Attachment metadata (filename, content-type, encoding)
- ✅ Client software (Outlook 12.0 from X-Mailer)
- ✅ Network metadata (IPs, ports, MACs, timestamps)

#### What WOULD BE Hidden Under TLS
- ❌ All SMTP commands and responses (encrypted)
- ❌ Authentication credentials (encrypted)
- ❌ Message envelope addresses (encrypted)
- ❌ Email headers (encrypted)
- ❌ Message body (encrypted)
- ❌ Attachment content (encrypted)
- ✅ IPs, ports, MACs, timestamps (metadata always visible)
- ✅ TLS handshake data (would reveal cert, cipher suite, TLS version)

### Critical Point
**Port number alone does not indicate encryption status.** A session on port 25 or 587 could still use STARTTLS. An analyst must examine the packet stream to verify:
1. STARTTLS command issued
2. TLS handshake present
3. Certificate exchange visible

This capture exhibits none of these, confirming plaintext transmission.

---

## 8. Attack Surface and Risk Assessment

### Vulnerabilities in This Session

| Vulnerability | Impact | Severity |
|---|---|---|
| **Plaintext credentials** | Attacker can recover username/password by capturing traffic | 🔴 Critical |
| **Plaintext message content** | Email body and attachments fully readable in capture | 🔴 Critical |
| **Predictable Message-IDs** | Exchange Message-ID format may reveal email server patterns | 🟡 Medium |
| **Banner information disclosure** | Exim 4.69 version revealed (facilitates targeting of known exploits) | 🟡 Medium |
| **No DKIM/SPF/DMARC** | No cryptographic message authentication | 🟠 High |
| **Client fingerprinting** | X-Mailer reveals Outlook 2007 generation; enables client-specific attacks | 🟡 Medium |
| **PIPELINING enabled** | Can be misused in certain attack scenarios | 🟡 Low |

### Real-World Incident Implications
If this were a **live forensic investigation**, the analyst would:
1. Alert the user that credentials were transmitted in plaintext
2. Recommend immediate password reset for the exposed account
3. Search for evidence of credential misuse (lateral movement, unauthorized access)
4. Check for data exfiltration or further compromise
5. Recommend organization-wide STARTTLS/SMTPS enforcement

---

## 9. Attachment Analysis

### NEWS.txt
| Attribute | Value |
|-----------|-------|
| **Filename** | NEWS.txt |
| **Content-Type** | text/plain |
| **Content-Transfer-Encoding** | 7bit (ASCII text, no encoding needed) |
| **Status** | Present in capture; content embedded in DATA fragments |
| **Recovery** | Full recovery possible; would require MIME boundary parsing |

### Note
This lab does not extract the attachment's content (it remains embedded in the MIME structure). A full forensic analysis would:
1. Parse MIME boundaries
2. Extract the attachment payload
3. Verify file signatures (magic bytes)
4. Scan for malware
5. Analyze file metadata and embedded objects

---

## 10. Chain of Custody and Evidence Integrity

### Evidence File Handling
| Step | Action | Status |
|------|--------|--------|
| **Original Preservation** | smtp.pcap stored unmodified in evidence/ | ✅ Preserved |
| **SHA-256 Hashing** | Original file hashed before any analysis | ✅ Recorded |
| **Working Copy** | Timestamp-preserved copy created | ✅ Copied |
| **Hash Verification** | Working copy hash matches original | ✅ Verified |
| **Analysis** | All work performed on working copy only | ✅ Separated |
| **Credential Masking** | Public report masks sensitive values | ✅ Applied |
| **Protected Appendix** | Full credentials in protected-access file | ✅ Segregated |

### SHA-256 Evidence Record
Both the original and working-copy files must have **identical SHA-256 hashes**. Example:

```
[original hash]   evidence/smtp.pcap
[working hash]    working/smtp_working.pcap
# Both hashes must match exactly
```

---

## 11. Forensic Findings Table (Required)

| Question | Finding |
|----------|---------|
| **1. When did the SMTP session start and end?** | 5 October 2009, 01:05:54 UTC-0500 (server) / 11:36:07 +0530 (message sender). Capture-relative: t=0.727603 s to t=4.895535 s (~4.17 seconds). Session closed with QUIT + 221 closing connection. |
| **2. What is the client IP address, port, and MAC?** | IP: 10.10.1.4 · MAC: 00:e0:1c:3c:17:c2 (Cradlepoint last-hop router) · Port: 1470 (ephemeral). |
| **3. What is the server IP address, port, and MAC?** | IP: 74.53.140.153 · MAC: 00:1f:33:d9:81:60 (Netgear last-hop router) · Port: 25 (SMTP). |
| **4. What is the SMTP server banner?** | "220 xc90.websitewelcome.com ESMTP Exim 4.69 #1 Mon, 05 Oct 2009 01:05:54 -0500" |
| **5. What email client software was used?** | Microsoft Office Outlook 12.0 (Outlook 2007 generation) — identified from X-Mailer header. |
| **6. What authentication method was used?** | AUTH LOGIN with Base64-encoded username and password. |
| **7. Who sent the email and to whom?** | From: "Gurpartap Singh" <gurpartap@patriots.in> To: <raj_deol2002in@yahoo.co.in> Subject: SMTP |
| **8. What is the message body (main content)?** | "Hello / I send u smtp pcap file / Find the attachment / GPS" |
| **9. What MIME structure does the message have?** | multipart/mixed containing multipart/alternative (text/plain + text/html) plus one text/plain attachment (NEWS.txt). |
| **10. Is there an attachment? If so, what is it?** | Yes — NEWS.txt (text/plain, 7bit encoding). Content embedded in MIME structure; full extraction requires boundary parsing. |
| **11. Was encryption used (STARTTLS or SMTPS)?** | No. tshark queries for STARTTLS command and TLS handshake both return 0 frames. Session is plaintext SMTP on port 25. |
| **12. What would be hidden if encryption were used?** | All application-layer data (commands, responses, credentials, headers, body, attachments) would be encrypted. Only metadata (IPs, ports, MACs, timestamps, TLS metadata) would remain visible. |

---

## 12. Mitigation and Detection Recommendations

### Detection
Organizations should alert on:
- SMTP AUTH commands without preceding STARTTLS
- Plaintext SMTP traffic on port 25 from user endpoints
- AUTH LOGIN mechanism in use (prefer more secure auth mechanisms)
- Failed STARTTLS negotiations followed by plaintext transmission
- Credentials discovered in packet captures (incident response)

### Mitigation
- **Enforce STARTTLS** on mail servers and configure clients to require it
- **Deprecate AUTH LOGIN** in favor of CRAM-MD5, XOAUTH2, or app passwords
- **Block outbound port 25** from user networks; require 587 with STARTTLS
- **Use MTA-STS and DANE** to prevent downgrade attacks
- **Implement SPF/DKIM/DMARC** for message authentication
- **Configure client-side TLS-only** enforcement in Outlook/Thunderbird

### Forensic Practice
- Retain full packet captures during incident response (not just flow data)
- Synchronize clocks across mail servers and endpoints
- Preserve SMTP streams in both ASCII and hex formats
- Treat recovered credentials as confidential evidence
- Document encryption status and evidential implications
- Explain last-hop limitations for MAC addresses and NAT

---

## 13. Conclusion

This SMTP email capture demonstrates the forensic value and risks of plaintext email transmission. In the absence of encryption:
- The analyst can recover **every application-layer detail** of the email transaction
- Credentials are trivial to decode and exploit
- Message content and recipients are fully exposed
- Server software fingerprints enable targeted attacks

In modern incident response, the absence of STARTTLS/SMTPS represents both an investigative advantage (full recovery) and an operational risk (complete exposure).

**Key Takeaway:**  
Always verify encryption status by examining the packet stream, not the port number alone. Plaintext SMTP is fully recoverable; encrypted SMTP is application-layer opaque.

---

**Report Generated:** 12 September 2026  
**Course:** SBT-DF203 — Basic Networking Skills for Digital Forensics  
**Institution:** International Cybersecurity and Digital Forensics Academy (ICDFA)  
**Author:** Ibrahim Diseh Garba (2025/FWSD/11521)
