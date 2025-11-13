# AWS SIEM & Incident Response Lab – Deployment Guide

> **Author:** William Crockett
> **Purpose:** Deploy a fully self-contained SIEM lab in AWS to simulate reconnaissance and attack behavior, detect events via Wazuh, GuardDuty, and CloudWatch, and practice incident response.

---

##  Overview

This lab recreates a small, production-style environment designed for security testing and incident detection.

| Role             | Hostname/IP                                      | Purpose                                            |
| ---------------- | ------------------------------------------------ | -------------------------------------------------- |
| **Attacker**     | Kali EC2                                         | Conducts controlled scans and brute-force attempts |
| **Target**       | Ubuntu + nginx + Wazuh Agent (10.0.2.x)          | Simulates a vulnerable web server                  |
| **SIEM**         | Wazuh Manager + Dashboard (10.0.1.x)             | Aggregates alerts, logs, and detection data        |
| **AWS Services** | CloudTrail, GuardDuty, VPC Flow Logs, CloudWatch | Provides cloud-native telemetry                    |

---

## Prerequisites

* **AWS Account** with permissions for EC2, VPC, IAM, S3, CloudWatch, and GuardDuty
* **AWS CLI** configured (`aws configure`)
* Basic familiarity with SSH and Linux administration
* Security Group inbound rules allowing:

  * `TCP 80` (HTTP)
  * `TCP 443` (Wazuh Dashboard)
  * `TCP 1514` (Agent ↔ Manager)
  * `TCP 22` (SSH – restricted to your IP)
* Optional: VSCode with **Remote SSH** or a terminal-based workflow

---

## Architecture

```text
Attacker (Kali)
     │
     │  HTTP/Recon TCP 80
     ▼
Target (Ubuntu + Wazuh Agent)
     │  TCP 1514
     ▼
Wazuh Manager + Dashboard (10.0.1.89)
     │
     ├─ AWS Events (CloudTrail, VPC Flow Logs)
     ├─ GuardDuty (Threat Intelligence)
     └─ S3 Evidence Bucket
```

---

## Deployment Steps

### 1. Network Setup

```bash
aws ec2 create-vpc --cidr-block 10.0.0.0/16
aws ec2 create-subnet --vpc-id <vpc-id> --cidr-block 10.0.1.0/24 --availability-zone us-east-2a
aws ec2 create-subnet --vpc-id <vpc-id> --cidr-block 10.0.2.0/24 --availability-zone us-east-2a
aws ec2 create-internet-gateway
aws ec2 attach-internet-gateway --vpc-id <vpc-id> --internet-gateway-id <igw-id>
```

Add a route table and associate both subnets with the internet gateway.
Enable **auto-assign public IPs** for simplicity.

---

### 2. Instance Deployment

#### Wazuh Manager

* **AMI:** Ubuntu 22.04
* **Type:** t3.medium
* **Subnet:** 10.0.1.0/24
* **Security Group:** Allow inbound 1514 (UDP/TCP), 443 (HTTPS), 22 (SSH)

Install Wazuh:

```bash
curl -sO https://packages.wazuh.com/4.x/install.sh
sudo bash install.sh -a -i
```

Record dashboard login credentials (default `admin` password printed at install end).

#### Target (Ubuntu + nginx + Wazuh Agent)

* **AMI:** Ubuntu 22.04
* **Type:** t3.small
* **Subnet:** 10.0.2.0/24
* **Security Group:** Allow inbound 80 (HTTP), 22 (SSH), outbound 1514 to manager

```bash
sudo apt update && sudo apt install -y nginx
sudo systemctl enable nginx --now
```

Install Wazuh Agent:

```bash
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.8.0-1_amd64.deb
sudo dpkg -i wazuh-agent.deb
sudo systemctl stop wazuh-agent
sudo sed -i 's/MANAGER_IP="127.0.0.1"/MANAGER_IP="10.0.1.89"/' /var/ossec/etc/ossec.conf
sudo systemctl enable wazuh-agent --now
```

---

### 3. Attacker (Kali Linux)

* **AMI:** Kali Linux 2024
* **Type:** t3.small
* **Subnet:** public or same VPC (10.0.x.x)
* Tools preinstalled: `nmap`, `nikto`, `gobuster`, `hydra`, `curl`

---

### 4. AWS Telemetry Configuration

#### CloudTrail

```bash
aws cloudtrail create-trail --name siem-lab-trail --s3-bucket-name <bucket-name> --is-multi-region-trail
aws cloudtrail start-logging --name siem-lab-trail
```

#### VPC Flow Logs + GuardDuty

```bash
# Role and log group created beforehand
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids <vpc-id> \
  --traffic-type ALL \
  --log-group-name "/aws/vpc/flowlogs" \
  --deliver-logs-permission-arn arn:aws:iam::<account-id>:role/VPCFlowLogsRole \
  --region us-east-2

aws guardduty create-detector --enable
```

Confirm delivery:

```bash
aws ec2 describe-flow-logs
aws guardduty list-findings --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
```

---

### 5. Attack Simulation

Run from the Kali attacker:

```bash
# Reconnaissance
nmap -sS -sV --top-ports 100 -T4 10.0.2.125 -oA ~/results/nmap-top100

# Web enumeration
gobuster dir -u http://10.0.2.125/ -w /usr/share/wordlists/dirb/common.txt -t 40 -o ~/results/gobuster.txt

# Vulnerability scan
nikto -h http://10.0.2.125 -output ~/results/nikto.txt

# SSH brute-force demo (limited)
for p in $(head -n 10 /usr/share/wordlists/rockyou.txt); do
  sshpass -p "$p" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ubuntu@10.0.2.125 false;
done
```

---

### 6. Evidence Collection

Each host runs a local evidence script:

```bash
~/collect_attacker_home.sh phase1
~/collect_target_home.sh phase1
~/collect_manager_home.sh phase1
```

Each script:

* Collects logs (`/var/log/nginx/`, `/var/ossec/logs/alerts.log`)
* Generates SHA256 manifest
* Creates a tarball under `~/evidence/`

Transfer to local machine:

```bash
scp ubuntu@10.0.2.125:~/evidence/*.tar.gz ~/evidence-local/target/
scp wazuh@10.0.1.89:~/evidence/*.tar.gz ~/evidence-local/manager/
scp kali@<attacker-ip>:~/evidence/*.tar.gz ~/evidence-local/attacker/
```

---

### 7. Verification & Detection

1. **Wazuh Dashboard:**

   * Navigate to `https://<manager-public-ip>`
   * Filter alerts by Target IP or Attacker IP

2. **GuardDuty Console:**

   * Check for findings under *Recon:EC2/PortProbe* or *SSHBruteForce*.

3. **CloudWatch Logs:**

   * Inspect `/aws/vpc/flowlogs` for matching source/destination pairs.

4. **Cross-correlate timestamps** between tools, Wazuh, and GuardDuty.

---

## Deliverables

| Evidence                          | Source        |
| --------------------------------- | ------------- |
| Wazuh alerts & JSON logs          | Wazuh Manager |
| nginx / auth logs                 | Target        |
| nmap / gobuster / nikto results   | Attacker      |
| VPC Flow Logs, GuardDuty findings | AWS           |
| Final incident report             | Analyst       |

---

##  Cleanup

Terminate all instances and stop logging when done:

```bash
aws ec2 terminate-instances --instance-ids <ids>
aws cloudtrail stop-logging --name siem-lab-trail
aws guardduty delete-detector --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
```

---

##  References

* [Wazuh Documentation](https://documentation.wazuh.com/current/)
* [AWS GuardDuty User Guide](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
* [AWS CloudTrail Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)

