# Network Threat Hunt: Long Connections, Beaconing & DNS Anomalies

**Tools:** Wireshark, Kali Linux | **Type:** Academic lab | **Dataset:** `sample-200.pcap` (4,156,081 packets)
**Skills:** Packet analysis, threat hunting, beacon detection, DNS analysis

## Overview
A hunt through a large packet capture for the three signals SOC analysts look for first: **unusually long connections**, **regular-interval "beacon" traffic**, and **abnormal DNS behavior**. The goal was to find suspicious hosts and explain *why* they looked suspicious, without relying on pre-built alerts.

## Lab Setup
- Analysis workstation: Kali Linux VM
- Tool: Wireshark (Statistics > Conversations, display filters, Delta time column)
- Data: course-provided capture, `sample-200.pcap`. The capture file is not included in this repo.

## Hunt 1: Long-lived connections
Sorting TCP conversations by duration (130,867 TCP conversations in the capture) surfaced several connections lasting roughly **86,000 seconds (about 24 hours)** while moving almost no data, around 6-8 bits/s in each direction.

<img width="1916" height="974" alt="01-long-connections" src="https://github.com/user-attachments/assets/2eb3af8e-cc28-4792-9577-313ea1542bfe" />

**Why it matters:** Legitimate sessions usually end. A connection that stays open for a full day at a trickle of traffic can indicate a persistent remote-access channel or command-and-control (C2) session.

## Hunt 2: Beaconing
Filtering traffic from `192.168.88.2` to `165.227.88.15` and adding a **Delta time** column showed DNS queries leaving at a near-constant interval of about **1.07 seconds**. 108,908 packets matched this filter.

<img width="953" height="821" alt="02-dns-beacon-interval" src="https://github.com/user-attachments/assets/acc2ed22-6363-46ee-80cf-669280809706" />


**Why it matters:** Human-driven traffic is irregular. Machine-driven check-ins at a fixed interval to an external address are a classic beaconing pattern. DNS is a common channel for this because it is rarely blocked.

## Hunt 3: DNS failures (NXDOMAIN)
Filtering with `dns.flags.rcode == 3` isolated "No such name" responses. Many were for internal-style names such as `wpad.Win.Lab` and `_ldap._tcp...Win.Lab` that were answered by public root servers.

<img width="1586" height="821" alt="03-nxdomain-responses" src="https://github.com/user-attachments/assets/e233709c-66b2-4af5-82ed-b53f66abc889" />


**Why it matters:** Internal Active Directory names should resolve inside the network. Seeing them sent to the internet points to DNS misconfiguration. It also leaks internal naming information, and wpad lookups are a known target for hijacking.

## Assessment
| Finding | Indicator | Confidence |
|---|---|---|
| Day-long low-bandwidth connections | Duration vs. data volume | Suspicious, needs endpoint context |
| Fixed-interval DNS to `165.227.88.15` | ~1.07 s Delta time | High that it is automated; C2 or DNS tunneling needs further analysis |
| Internal names leaking to root servers | NXDOMAIN on `Win.Lab` names | Likely misconfiguration |

## What I would do next in a real SOC
1. Check the destination `165.227.88.15` against threat intelligence and passive DNS.
2. Inspect the query names and lengths for tunneling signs (high entropy, long labels).
3. Identify the process on `192.168.88.2` generating the traffic and escalate.
4. Search other hosts for contact with the same destination.

## Limitations
This was a lab dataset analyzed in Wireshark only. I did not have endpoint logs or threat-intel lookups, so these are indicators for investigation, not confirmed compromise.

## What I Learned
- Duration and Delta time are simple but powerful hunting pivots.
- A strong analyst separates "automated" from "malicious" and says what evidence would settle it.
