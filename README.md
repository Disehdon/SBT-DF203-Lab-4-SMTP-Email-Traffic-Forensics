markdown
<div align="center">

# SBT-DF203 · Lab 4 — SMTP Email Traffic Forensics

**Network Forensics · SMTP Protocol Analysis · Email Reconstruction**

</div>

---

## Author

| Field | Detail |
| :--- | :--- |
| **Student** | Ibrahim Diseh Garba |
| **Registration No.** | `2025/FWSD/11521` |
| **Programme** | Fellowship in Web Application Security & Digital Forensics |
| **Institution** | International Cybersecurity and Digital Forensics Academy (ICDFA) |
| **Course** | SBT-DF203 — Basic Networking Skills for Digital Forensics |
| **Instructor** | Aminu Idris, AMCPN |
| **Delivery Block** | 2/3 of 3 |
| **Submission Date** | 14 September 2026 |

<div align="center">

[![Course](https://img.shields.io/badge/course-SBT--DF203-blue)](https://icdfa.edu.ng)
[![Institution](https://img.shields.io/badge/institution-ICDFA-darkred)](https://icdfa.edu.ng)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94?logo=kali-linux&logoColor=white)](https://kali.org)
[![Tool](https://img.shields.io/badge/tool-TShark%204.6.6-blue?logo=wireshark&logoColor=white)](https://wireshark.org)
[![Tool](https://img.shields.io/badge/tool-Python%203.14-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-Academic-lightgrey)](#license)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Objectives](#objectives)
- [Methodology](#methodology)
- [Key Findings](#key-findings)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
- [Analysis Commands](#analysis-commands)
- [Evidence and Chain of Custody](#evidence-and-chain-of-custody)
- [Encryption Assessment](#encryption-assessment)
- [Detection and Mitigation](#detection-and-mitigation)
- [Safety and Ethics](#safety-and-ethics)
- [References](#references)
- [License](#license)

---

## Overview

This repository contains the complete forensic analysis of a historical SMTP email capture (`smtp.pcap`) supplied by ICDFA as an authorised training artefact. The capture records a single SMTP session between a private client network (`10.10.1.4`) and a public Exim mail server (`74.53.140.153`) that took place on **5 October 2009**.

The session was **plaintext SMTP on port 25** with **no STARTTLS negotiation**. As a result, the entire SMTP dialogue — including the Base64-encoded authentication exchange, envelope addresses, message headers, and complete message body with attachment — was recoverable from the packet stream.

The analysis demonstrates both the investigative value of packet-level SMTP analysis and the evidential boundaries imposed by encryption.

---

## Objectives

1. Explain the role of SMTP and distinguish plaintext SMTP, STARTTLS, and implicit TLS.
2. Identify SMTP commands, server response codes, and authentication exchanges.
3. Reassemble an SMTP TCP stream and reconstruct message headers and body.
4. Decode Base64 values in a controlled offline manner.
5. Extract timestamps, client software, IP addresses, ports, and MAC addresses.
6. Assess evidential limitations when encryption is used or the capture is incomplete.

---

## Methodology

The analysis followed the ICDFA Lab 4 workflow:

| Phase | Description | Output |
| :---: | :--- | :--- |
| **1** | Inventory the capture and locate SMTP streams | `reports/tcp_conversations.txt`, `reports/smtp_packet_inventory.tsv` |
| **2** | Extract SMTP commands and response codes | `reports/smtp_commands_responses.tsv` |
| **3** | Decode Base64 authentication parameters offline | `reports/base64_decode_masked.txt` |
| **4** | Reconstruct the email via Follow TCP Stream | `reports/smtp_stream_0.txt`, `reports/message_headers.txt` |
| **5** | Extract client, host, and network metadata | `reports/smtp_network_metadata.tsv`, `reports/client_indicators.tsv` |
| **6** | Assess STARTTLS / TLS and evidential limitations | `reports/tls_assessment.txt` |

### Environment

| Component | Version |
| :--- | :--- |
| OS | Kali Linux (ICDFA lab VM) |
| TShark | `4.6.6-1` |
| Wireshark | `4.6.6-1` |
| Python | `3.14.6` |
| Interface | Offline pcap analysis — no live capture |

---

## Key Findings

| Indicator | Value |
| :--- | :--- |
| Session date | 5 October 2009 (02:06:07 – 02:06:16 UTC) |
| Session duration | 9.198 seconds (full capture); 7.578 s SMTP stream |
| Client endpoint | `10.10.1.4:1470` |
| Server endpoint | `74.53.140.153:25` |
| Server software | Exim 4.69 on `xc90.websitewelcome.com` |
| Client software | Microsoft Office Outlook 12.0 (from `X-Mailer`) |
| Authentication | `AUTH LOGIN` with Base64-encoded credentials |
| Envelope sender | `<gurpartap@patriots.in>` |
| Envelope recipient | `<raj_deol2002in@yahoo.co.in>` |
| Message subject | `SMTP` |
| Message body | `multipart/mixed` (text/plain + text/html + attachment) |
| Attachment | `NEWS.txt` |
| STARTTLS / TLS | **Not observed** — plaintext SMTP on port 25 |
| Total packets | 60 |

### Verdict

The capture demonstrates a **fully recoverable plaintext SMTP transaction**. Every application-layer artefact — credentials, envelope, headers, and body — was extractable because no TLS encryption was negotiated. This confirms both the investigative value of packet-level analysis and the critical importance of transport encryption in modern email environments.

---

## Repository Structure

### Top-level layout
SBT-DF203-Lab4-2025-FWSD-11521/
├── README.md
├── SBT-DF203-Lab4_2025-FWSD-11521_Ibrahim_Diseh_Garba.pdf
├── evidence/
├── working/
├── exported/
├── reports/
├── screenshots/
└── scripts/
text

### Directory contents

| Directory | Contents | Purpose |
| :--- | :--- | :--- |
| `evidence/` | `smtp.pcap` (26 KB, 60 packets) | Original capture — preserved unmodified |
| `working/` | `smtp_working.pcap` | Timestamp-preserved analysis copy |
| `exported/` | Recovered MIME parts, attachments | Objects extracted from the stream |
| `reports/` | 12 × `.tsv` / `.txt` / `.md` files | TShark analysis outputs and hashes |
| `screenshots/` | 16 × `.png` figures | Numbered evidence screenshots |
| `scripts/` | `base64_decoder.py` | Offline Base64 decoding script |

### `reports/` — analysis output files

| File | Description |
| :--- | :--- |
| `smtp_capture_hashes.txt` | SHA-256 of original and working copy |
| `smtp_capinfos.txt` | Full capture metadata summary |
| `tcp_conversations.txt` | TCP conversation list |
| `smtp_packet_inventory.tsv` | SMTP frame inventory |
| `smtp_commands_responses.tsv` | SMTP command / response timeline |
| `base64_decode_masked.txt` | Masked Base64 decode output |
| `smtp_stream_0.txt` | Full TCP stream reconstruction |
| `message_headers.txt` | Extracted RFC 5322 headers |
| `smtp_network_metadata.tsv` | MAC / IP / port mapping |
| `client_indicators.tsv` | Client software identification |
| `reconstructed_email_redacted.txt` | Redacted email reconstruction |
| `protected_appendix.md` | Full decoded credentials — **excluded from public ZIP** |

### `screenshots/` — numbered evidence figures

| Group | Files |
| :--- | :--- |
| **Section 3 — Environment** | `fig_3.1_folder_structure.png` · `fig_3.2_tools_installed.png` · `fig_3.3_capture_hashes.png` |
| **Section 4 — Inventory** | `fig_4.1_tcp_conversations.png` · `fig_4.2_packet_inventory.png` |
| **Section 5 — Commands** | `fig_5.1_command_timeline.png` · `fig_5.2_220_banner.png` · `fig_5.3_ehlo_auth.png` |
| **Section 6 — Base64** | `fig_6.1_masked_decode.png` |
| **Section 7 — Reconstruction** | `fig_7.1_follow_stream.png` · `fig_7.2_message_headers.png` · `fig_7.3_redacted_email.png` |
| **Section 8 — Metadata** | `fig_8.1_network_metadata.png` · `fig_8.2_wireshark_details.png` · `fig_8.3_xmailer.png` |
| **Section 9 — Encryption** | `fig_9.1_tls_assessment.png` |

---

## Getting Started

### Prerequisites

- Kali Linux (or Debian-based distribution)
- `sudo` privileges
- Network access to download the training capture

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Disehdon/SBT-DF203-Lab4-SMTP-Forensics.git
cd SBT-DF203-Lab4-SMTP-Forensics

# 2. Install dependencies
sudo apt update
sudo apt install -y wireshark tshark python3 wget

# 3. Verify tools
tshark --version
python3 --version
Running the Analysis
See Analysis Commands for the complete TShark command set used to regenerate the outputs in reports/.
 
Analysis Commands
The following commands regenerate every artefact in the reports/ directory.
Capture Integrity and Metadata
bash
cp --preserve=timestamps evidence/smtp.pcap working/smtp_working.pcap
sha256sum evidence/smtp.pcap working/smtp_working.pcap | tee reports/smtp_capture_hashes.txt
capinfos evidence/smtp.pcap | tee reports/smtp_capinfos.txt
TCP Conversation Inventory
bash
tshark -r working/smtp_working.pcap -q -z conv,tcp | tee reports/tcp_conversations.txt
SMTP Command / Response Extraction
bash
tshark -r working/smtp_working.pcap \
  -Y 'smtp.req || smtp.rsp' -T fields \
  -e frame.number -e frame.time -e ip.src -e ip.dst \
  -e tcp.srcport -e tcp.dstport \
  -e smtp.req.command -e smtp.req.parameter \
  -e smtp.response.code \
  -e _ws.col.Info \
  | tee reports/smtp_commands_responses.tsv
Follow TCP Stream
bash
tshark -r working/smtp_working.pcap -q -z follow,tcp,ascii,0 \
  | tee reports/smtp_stream_0.txt
Message Header Extraction
bash
grep -Ei '^(Date|From|To|Subject|Message-ID|MIME-Version|Content-Type|X-Mailer):' \
  reports/smtp_stream_0.txt \
  | tee reports/message_headers.txt
Network Metadata (MAC / IP / Port)
bash
tshark -r working/smtp_working.pcap -Y 'smtp' -T fields \
  -e frame.number -e frame.time_epoch -e eth.src -e eth.dst \
  -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.stream \
  | tee reports/smtp_network_metadata.tsv
Encryption Check
bash
echo "STARTTLS frames:"; tshark -r working/smtp_working.pcap -Y 'smtp.starttls' | wc -l
echo "TLS handshake frames:"; tshark -r working/smtp_working.pcap -Y 'tls.handshake.type == 1' | wc -l
Offline Base64 Decoding
bash
python3 scripts/base64_decoder.py | tee reports/base64_decode_masked.txt
 
Evidence and Chain of Custody
Original capture preserved unmodified. All analysis performed on a timestamp-preserved working copy. Hashes recorded below and stored in reports/smtp_capture_hashes.txt.
File	Size	SHA-256
evidence/smtp.pcap	26 KB	17ad230db1b6fd5dd18eb311092df1cf6eb162054bdb47697b89bef5a86a47ab
working/smtp_working.pcap	26 KB	17ad230db1b6fd5dd18eb311092df1cf6eb162054bdb47697b89bef5a86a47ab
Integrity confirmed. The original and working copy are byte-identical.
Capture Metadata (from capinfos)
Field	Value
Data size	26 KB
Capture duration	9.198384 seconds
Earliest packet	2009-10-05 02:06:07.492060 UTC
Latest packet	2009-10-05 02:06:16.690444 UTC
Total packets	60
Encapsulation	Ethernet
SHA-1	3def1a1fed849e7f23b66e6925ddff05845a400b
Case Metadata
Field	Value
Case ID	SBT-DF203-Lab4-2025-FWSD-11521
Analyst	Ibrahim Diseh Garba
Registration No.	2025/FWSD/11521
Evidence source	ICDFA-supplied historical capture
Analysis workstation	Kali Linux VM (ICDFA lab)
Reporting Rule Applied
Credentials recovered from the capture are masked in this README and in the report body. The masking convention is:
•	Username: first two characters + masked middle + full domain (gu********@patriots.in)
•	Password: first two + masked middle + last character (pu*******3)
Full values are stored only in reports/protected_appendix.md, which is excluded from the public submission package per the lab manual's two-tier reporting rule.
 
Encryption Assessment
Check	Result
STARTTLS command observed?	No
tls.handshake.type == 1 frames?	0
smtp.starttls frames?	0
Implicit TLS (port 465)?	Not applicable — port 25
Session encryption?	None — plaintext
What Remains Visible vs. Hidden Under TLS
Artefact	Visible Here	Would Be Hidden Under TLS
Server banner	✅	✅
EHLO / HELO	✅	✅
AUTH LOGIN mechanism	✅	✅
Base64 credentials	✅	✅
MAIL FROM / RCPT TO	✅	✅
Message headers and body	✅	✅
Source / destination IPs and ports	✅	❌ (metadata)
Timestamps and byte counts	✅	❌ (metadata)
Evidential note: Port number alone does not prove absence of encryption. A port-25 session can be encrypted via STARTTLS negotiated after the greeting. Here, the packet stream contains no STARTTLS command and no TLS handshake, so the analyst can state with confidence that the session was conducted in plaintext.
 
Detection and Mitigation
Detection Controls
Control	Description
Plaintext SMTP alerting	Alert when SMTP sessions on port 25 carry AUTH commands without a preceding STARTTLS
Credential-in-flight detection	Flag any AUTH LOGIN / AUTH PLAIN seen in cleartext
Port 25 egress restrictions	Block outbound port 25 from user networks
TLS downgrade monitoring	Alert when a TLS-capable server falls back to plaintext
Mitigation Controls
Control	Description
Enforce STARTTLS	Require STARTTLS on 25/587, or use implicit TLS on 465
Deprecate AUTH LOGIN	Move to AUTH CRAM-MD5, AUTH XOAUTH2, or app passwords
MTA-STS and DANE	Publish policy and TLSA records to prevent downgrade
SPF / DKIM / DMARC	Add cryptographic authentication to outbound email
Client-side TLS-only	Configure Outlook / Thunderbird to refuse unencrypted SMTP
Forensic Practice
•	Retain full packet capture during incidents — not just flow data.
•	Synchronise system clocks across mail servers and clients.
•	Preserve SMTP stream data in both ASCII and hex form.
•	Treat recovered credentials as confidential; mask in public reporting.
•	Document whether the capture was taken at the client, relay, or destination — this determines MAC relevance.
 
Safety and Ethics
This lab was conducted exclusively as an offline analysis of a supplied historical capture. No live traffic was generated, intercepted, or replayed.
•	Original smtp.pcap preserved unmodified; analysis performed on a timestamp-preserved working copy.
•	No credentials were used to access any live system, and no messages were sent or replayed.
•	Recovered credentials and message content were masked in the report body; full values appear only in the protected evidence appendix.
•	No third-party system, production network, or public infrastructure was targeted.
Warning: The scripts/base64_decoder.py script is intended for authorised training analysis only. Do not use it to decode credentials from any capture you are not explicitly authorised to analyse.
 
References
1.	ICDFA. (2026). SBT-DF203 — Module 3: SMTP Email Traffic Forensics — Course Materials.
2.	ICDFA. (2026). SBT-DF203 Lab 4 — SMTP Email Traffic Forensics — Official Lab Manual.
3.	RFC 5321. (2008). Simple Mail Transfer Protocol. IETF
4.	RFC 3207. (2002). SMTP Service Extension for Secure SMTP over TLS. IETF
5.	RFC 4954. (2007). SMTP Service Extension for Authentication. IETF
6.	RFC 2045. (1996). MIME Part One: Format of Internet Message Bodies. IETF
7.	RFC 4648. (2006). The Base16, Base32, and Base64 Data Encodings. IETF
8.	Wireshark Foundation. (2026). SampleCaptures — smtp.pcap. wiki.wireshark.org
9.	Microsoft. (2009). Outlook 12.0 Message Format Reference.
 
License
This repository is submitted as academic coursework for SBT-DF203 Lab 4 at ICDFA. The contents may not be redistributed, reused, or reproduced without written permission from the author and ICDFA.
© 2026 Ibrahim Diseh Garba. All rights reserved.

<img width="451" height="692" alt="image" src="https://github.com/user-attachments/assets/fc4fe295-d7dd-4e91-b184-6d29f72371ef" />
