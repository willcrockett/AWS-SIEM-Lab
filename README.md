# AWS SIEM Lab Using Wazuh

This project demonstrates an end-to-end SIEM pipeline built in AWS using Wazuh as the central analysis platform. It collects CloudTrail logs, VPC Flow Logs, and host-level events from an EC2 web server, then correlates those events with controlled reconnaissance and vulnerability scans (Nmap, Nikto, Gobuster). The goal is to show practical detection, log analysis, and security operations fundamentals.

---

## 1. Architecture Overview
<img width="1667" height="982" alt="network-diagram" src="https://github.com/user-attachments/assets/f10cec3d-afc6-401c-b769-cb7ef6992ef5" />


**Components**

- **Kali Attacker:** generates recon scans
    
- **Target EC2 instance:** NGINX webserver serving on port 80
    
- **Wazuh agent:** installed on target to forward host logs
    
- **Wazuh manager:** central log analysis, rules, and alerting
    
- **AWS logging services:** CloudTrail + VPC Flow Logs feeding into Wazuh
    

---

## 2. Objectives

- Deploy a minimal, reproducible cloud SIEM environment
    
- Generate real reconnaissance activity and capture resulting logs
    
- Validate ingestion, parsing, and alerting across multiple log sources
    
- Demonstrate end-to-end detection: recon → logs → Wazuh events
    

---

## 3. Environment Setup

**AWS Services**

- EC2 (attacker + target + Wazuh manager)
    
- CloudTrail (management events + S3 delivery)
    
- VPC Flow Logs (network-level telemetry)
    

**Wazuh Configuration**

- Wazuh manager installed on separate EC2 instance
    
- Agent installed on target EC2 instance
    
- Default rulesets enabled, including web server and recon detection
    

Refer to `deployment_steps.md` for details.

---

## 4. Reconnaissance Activity

To generate detectable events, the following tools were used:

### Nmap

- Quick port/version scan:  
```
# quick SYN probe of the top 100 TCP ports
$ nmap -sS -sV --top-ports 100 -T4 -oA "$OUT"/nmap-top100 <TARGET IP>
```
    
- Web vulnerability scripts:  
~~~
# scan for webserver vulnerabilities
$ nmap -sV --script=http-vuln* -p80 <TARGET IP> -oN "$OUT"/nmap-nse-http.txt 2>&1 | tee "$OUT"/nmap-nse.full.txt
~~~
    

### Nikto

~~~
# scan the webserver for potential vulnerabilities
$ nikto -h http://<TARGET IP> -output "$OUT"/nikto.txt 2>&1 | tee "$OUT"/nikto.full.txt
~~~

### Gobuster

~~~
# look for common webserver directory/file structures via bruteforce
$ gobuster dir -u http://<TARGET IP>/ -w /usr/share//seclists/Discovery/Web-Content/common.txt -t 40 -o "$OUT"/gobuster.txt 2>&1 | tee "$OUT"/gobuster.full.txt
~~~
Outputs for each tool are stored in `/log_samples`.

---

## 5. Detection and Log Analysis

This section is where your screenshots belong. Use this structure for consistency.

### 5.1 Example: Nmap vulnerability scan

**Command executed**

~~~
$ nmap -sV --script=http-vuln* -p80 <TARGET IP> -oN "$OUT"/nmap-nse-http.txt 2>&1 | tee "$OUT"/nmap-nse.full.txt
~~~

**Finding**  
The scan identified a potential (albeit low-priority and likely a false positive) **HTTP DoS-related vulnerability** on port 80.  
![[Pasted image 20251113121245.png]]
*from nmap-nse.full.txt*

---

### 5.2 How the activity appeared in Wazuh

**Dashboard event**
![[3-vulver-nmapnse.png]]
![[Pasted image 20251113121516.png]]
Brief caption:

> Wazuh detected the vulnerability-oriented scan as multiple HTTP 400 responses to the same source and raised HTTP-related reconnaissance and anomaly alerts, mapping them to the correct rule categories and severity levels.

**Raw Wazuh alert log**  

![[Pasted image 20251113121822.png]]
> The log entry contains source IP, target IP, method, URL path, and associated rule IDs, confirming end-to-end ingestion and rule execution.

---

### 5.3 Additional Recon Events

Outputs of other commands run from the attacker can be found under `evidence/attacker/<phase>`

Corresponding wazuh dashboard screenshots and event json outputs can be found under `screenshots`

Raw alert logs can be found under `evidence/manager/<phase>`

---

## 6. Detection Queries & Rules

### Detection Queries & Rules

**Custom Rules:**  
None. This lab used Wazuh’s default rule set with no local rule modifications.

**Triggered Built-In Rules:**

- **31103 (web_scan):** Flagged Nmap NSE HTTP-vulnerability scanning activity.
    
- **20007 (syslog anomalies):** Logged repeated abnormal HTTP requests during enumeration.
    
- **9902 (ossec generic scan):** Detected high-frequency service probing.
    

**Correlation Logic:**  
Wazuh’s rule engine correlated repeated HTTP anomalies, elevated scan frequency, and known Nmap-signature patterns to raise multi-stage alerts.

**Tuning Notes:**  
No tuning applied. In a production environment, rate-based rules and recon signatures would typically be tuned to reduce noise from known scanner IPs or scheduled vulnerability scans.

---

## 7. Key Findings

State the value plainly:

- Reconnaissance and vulnerability scans produce clear, classifiable event signatures
    
- Host-level, network-level, and cloud-level logs correlated correctly
    
- Wazuh rules triggered reliably and provided actionable context
    
- The environment validates practical SOC skills in log interpretation and alert analysis
    

---

## 8. Repository Structure

/screenshots 
/evidence 
/analysis
deployment_steps.md 
README.md`

---

## 9. Future Improvements

Things I would like to add in the future to continue building on the skills developed here thus far:

* Create an exploitable endpoint on the target webserver then exploit it from the attacker (metasploit). Document relevant Wazuh events
* Create custom wazuh logic to filter out false positives
* Integrate VPC flow flogs with Wazuh
- Add Windows server logs
- Add automated alert escalation
- Expand to include IDS (Suricata) for packet-level visibility

---
