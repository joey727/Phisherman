# Phisherman - Phishing URL Detection Platform

Phisherman is a lightweight phishing-detection backend built with **Node.js**, **Express**, and **TypeScript**.  
It analyzes URLs using multiple threat-intelligence feeds, DNS-level security checks, and heuristic rules to determine whether a URL is **safe**, **suspicious**, or **phishing**.

This project focuses on accuracy, efficiency, and strong network-security guarantees such as **SSRF protection** and **DNS rebinding detection**.

---

## Features

### Multi-Source Threat Intelligence
Phisherman checks URLs against:
- **URLHaus (Recent JSON Feed)**
- **OpenPhish (Community Feed)**
- **Google Safe Browsing API**

### Heuristic Analysis
Detects:
- Overly long or suspicious domains  
- Hostname abnormalities (`..`, `--`, mixed Unicode)  
- Common phishing patterns

### Strong SSRF Protection
Includes hardened network-layer defenses:
- Blocks private IP ranges  
- Blocks loopback (`127.x.x.x`) and link-local (`169.254.x.x`)  
- Detects DNS rebinding  
- Rejects malformed or unsafe hostnames

### Fast & Efficient
- Downloads threat feeds at startup  
- Refreshes feeds every 5 minutes  
- In-memory Set-based lookups for O(1) speed


