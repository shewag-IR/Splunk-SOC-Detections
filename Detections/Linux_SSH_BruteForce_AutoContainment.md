# 🐧 Automated Incident Response: Linux SSH Brute-Force Detection & Containment

## 📝 Project Overview
This project showcases a fully automated Security Operations Center (SOC) pipeline designed to detect, alert, and neutralize Linux SSH brute-force attacks. By integrating Wazuh (EDR), Splunk (SIEM), and Splunk SOAR, this architecture identifies rapid authentication failures followed by a successful login, instantly severing the attacker's connection and locking the compromised identity without manual analyst intervention.

## 🏗️ Architecture & Tech Stack
* **Cloud Infrastructure:** Google Cloud Platform (GCP)
* **Target Environment:** Ubuntu Linux Server
* **EDR:** Wazuh 
* **SIEM:** Splunk Enterprise
* **SOAR:** Splunk SOAR
* **Threat Intel:** VirusTotal API

---

## ⚙️ The Detection & Response Blueprint

### Step 1: Threat Emulation
To test the pipeline, a live credential stuffing attack was launched against the Linux server using Hydra:
`hydra -L users.txt -P passwords.txt ssh://<TARGET_IP> -t 6`

### Step 2: Detection Logic (Wazuh)
I engineered custom Wazuh rules targeting the `/var/log/auth.log` file. 
* **Rule 100007:** Detects the brute-force attempt (10 failed logins within 120 seconds from the same IP).
* **Rule 100008:** Triggers a high-severity alert if a successful login occurs from that exact IP immediately after the brute-force pattern.

```xml
<group name="syslog,sshd,">
  <rule id="100007" level="12" timeframe="120" frequency="10">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip/>
    <description>Multiple authentication failures from $(srcip), Possible Brute Force attack</description>
    <mitre>
      <id>T1110.001</id>    
    </mitre>
  </rule>
  
  <rule id="100008" level="15">
    <if_sid>5715</if_sid>
    <if_matched_sid>100007</if_matched_sid>
    <same_source_ip/>
    <description>Confirmed Successful authentication from $(srcip) for user: $(dstuser), After a Brute Force attack</description>
    <mitre>
      <id>T1110.001</id>
      <id>T1021</id>
      <id>T1078</id>     
    </mitre>
  </rule>
</group>
```

### Step 3: SIEM Aggregation & CEF Mapping (Splunk)
The Wazuh alerts are ingested into Splunk. I created the following SPL query to isolate Rule 100008 and normalize the fields.
By renaming data.srcip to sourceAddress and data.dstuser to destinationUserName, the data is perfectly mapped to the Common Event Format (CEF) standard before the webhook is pushed to Splunk SOAR.

```
index=wazuh rule.id=100008 
| rename data.srcip as sourceAddress 
| stats latest(_time) as Timestamp
values(agent.ip) as destinationAddress
values(data.dstuser) as destinationUserName 
values(agent.name) as devicehostName
count as Firedtime
values(rule.description) as RuleTrigger
by sourceAddress
| convert ctime(Timestamp)
```

### Step 4: Automated Containment (Splunk SOAR)
Upon receiving the Splunk alert, the Linux_AutoBlock_BruteForce playbook automatically executes a sequential, least-privilege defense strategy using safe OS commands:

**Network Containment (iptables):** Injects a DROP rule to sever the attacker's connection.
* Command Executed: `sudo /usr/sbin/iptables -A INPUT -s {artifact:*.cef.sourceAddress} -j DROP`

**Identity Containment (usermod):** Locks the compromised user account to prevent persistence.
* Command Executed: `sudo usermod -L {artifact:*.cef.destinationUserName}`

**Threat Intelligence Enrichment:** Queries the blocked IP against the VirusTotal v3 API for SOC reporting and IOC documentation.

## 📸 Playbook Configuration & Proof of Execution
(Add your screenshots here)

![Iptables Block Action](link-to-Screenshot-780)

![Usermod Lock Action](link-to-Screenshot-781)

![VirusTotal Enrichment](link-to-Screenshot-782)

## 🚀 Impact
This architecture successfully demonstrates automated containment mapped directly to the PICERL framework. By utilizing highly specific Wazuh rules, precision SPL mapping, and privileged OS command execution via SOAR, the SOC eliminates manual investigation time and neutralizes active compromises instantly.