# 🛡️ Splunk SOC L1 Detections & Investigations

This repository contains **SOC Level-1 detections, searches, and investigation notes** created using **Splunk Enterprise** in a hands-on SOC lab environment.

All detections and investigations are based on **real log sources**, realistic attack simulations, and practical SOC workflows — not theory-only examples.

---

## 👤 About This Repository

This repo focuses on **how Splunk is used by an L1 SOC analyst**, including:

- Writing SPL searches for threat detection
- Alert validation and tuning
- Log correlation across multiple data sources
- Differentiating **True Positives vs False Positives**
- Supporting investigations with evidence

It complements my **SOC Incident Reports repository**, where full incident investigations are documented.

---

## 🎯 What This Repository Demonstrates

- SOC L1 detection logic using **SPL**
- Alert triage mindset and workflow
- Endpoint, network, and authentication-based detections
- Evidence-driven analysis
- Practical SOC investigation thinking

---

## 🔍 Detection & Investigation Areas

### 🔹 Endpoint & Authentication
- Failed login patterns
- Brute-force attempts
- Abnormal process activity
- Privilege misuse indicators

### 🔹 Network & IDS
- Suricata alert analysis
- Suspicious inbound/outbound traffic
- Reconnaissance behavior
- Malicious IP validation

### 🔹 Web & Server Logs
- Web shell indicators
- Command execution attempts
- Abnormal request patterns
- Log-based anomaly detection

---

## 🛠️ Tools & Log Sources

- **Splunk Enterprise**
- Windows Security Event Logs
- Linux authentication & audit logs
- Web server logs (Apache)
- Suricata IDS alerts
- Wazuh (HIDS / EDR)

---

## 🧠 How This Repo Is Structured

Each detection or investigation typically includes:

1. Detection objective
2. Relevant SPL query
3. Log sources required
4. Why the behavior is suspicious
5. Alert validation steps
6. False positive considerations
7. Analyst next steps

---

## 🎓 Learning Objective

This repository is maintained to:

- Build **job-ready SOC L1 Splunk skills**
- Practice realistic alert detection and triage
- Improve investigation depth and accuracy
- Prepare for enterprise SOC environments

Content is continuously updated as new detections and investigations are added.

---

## 🔗 Related Repositories

- **SOC L1 Incident Reports:**  
  https://github.com/shewag-IR

---

## 📬 Contact

- **LinkedIn:** https://www.linkedin.com/in/analystshewag  
- **GitHub:** https://github.com/shewag-IR  

Open to feedback, collaboration, and SOC opportunities.