# 🔐 Splunk SSH Authentication Security Monitoring

<p align="center">

![Splunk](https://img.shields.io/badge/SIEM-Splunk-black?style=for-the-badge&logo=splunk)

![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Log%20Analysis-red?style=for-the-badge)

![SOC](https://img.shields.io/badge/SOC-Security%20Operations-blue?style=for-the-badge)

![SSH](https://img.shields.io/badge/Protocol-SSH-green?style=for-the-badge)

</p>

<p align="center">
<b>Splunk-based SSH authentication log analysis, security monitoring, suspicious activity detection and SOC dashboard.</b>
</p>

---

## 📌 Project Overview

This project demonstrates a practical **SOC / Blue Team security monitoring workflow** using **Splunk Enterprise**.

SSH authentication logs are analyzed using **Splunk Search Processing Language (SPL)** to identify failed authentication attempts, successful logins, suspicious source IP addresses, targeted user accounts and potential brute-force activity.

The project also includes a dedicated **Splunk Security Dashboard** for centralized monitoring and investigation.

---

## 🎯 Objectives

- Analyze SSH authentication logs in Splunk
- Identify repeated failed authentication attempts
- Analyze source IP addresses
- Identify targeted usernames
- Correlate failed and successful authentication
- Detect potentially suspicious authentication patterns
- Develop brute-force detection logic
- Build a SOC-style Splunk dashboard
- Practice security event investigation and triage

---

## 🛠️ Tools & Technologies

| Technology | Purpose |
|---|---|
| 🔥 Splunk Enterprise | SIEM & Security Monitoring |
| 🔎 SPL | Log Searching & Detection |
| 🔐 SSH | Authentication Event Source |
| 🐧 Linux | Security Environment |
| 🐙 GitHub | Documentation & Portfolio |

---

## 📊 Dataset

The project uses simulated SSH authentication data ingested into Splunk.

### Event Types

```text
Successful SSH Login
Failed SSH Login
Multiple Failed Authentication Attempts
Connection Without Authentication
```

### Dataset Statistics

| Event Type | Count |
|---|---:|
| Successful SSH Login | 918 |
| Failed SSH Login | 915 |
| Multiple Failed Authentication Attempts | 909 |
| Connection Without Authentication | 858 |
| **Total Events** | **3,600** |

> ⚠️ The dataset is simulated/educational data created for cybersecurity laboratory practice.

---

# 🖥️ Splunk Security Dashboard

A SOC-style Splunk dashboard is included in this project.

The dashboard provides visibility into:

- 📊 Total SSH events
- ❌ Failed SSH logins
- ✅ Successful SSH logins
- ⚠️ Unauthenticated connections
- 📈 Authentication activity
- 🌐 Top source IP addresses
- 👤 Most targeted accounts
- 🔐 Failed vs successful authentication
- 🚨 Suspicious authentication activity

### Dashboard Preview

📸 **Dashboard screenshot will be added here after dashboard creation.**

---

# 🔎 Investigation Methodology

The investigation follows a simplified SOC workflow:

```text
SSH AUTHENTICATION LOGS
          ↓
EVENT CLASSIFICATION
          ↓
FAILED LOGIN ANALYSIS
          ↓
SOURCE IP ANALYSIS
          ↓
TARGETED USER ANALYSIS
          ↓
FAILED + SUCCESSFUL CORRELATION
          ↓
SUSPICIOUS ACTIVITY DETECTION
          ↓
SOC INVESTIGATION
```

---

# 🚨 Detection Approach

The project correlates failed and successful SSH authentication attempts.

The primary triage condition is:

```text
Failed Logins >= 20
AND
Successful Logins > 0
```

This pattern can warrant investigation for:

- 🔐 Password guessing
- 🚨 Brute-force activity
- 🔑 Possible credential compromise
- 🤖 Automated authentication attempts

> ⚠️ This is a triage heuristic and does not independently prove compromise.

---

# 🧪 SPL Queries

## 1️⃣ Event Type Analysis

```spl
source="ssh_logs_new.json" host="Sanath" sourcetype="_json"
| stats count by event_type
| sort - count
```

---

## 2️⃣ Failed SSH Login Analysis

```spl
source="ssh_logs_new.json" host="Sanath" sourcetype="_json" event_type="Failed SSH Login"
| stats count by id.orig_h, username
| sort - count
```

---

## 3️⃣ Source IP Analysis

```spl
source="ssh_logs_new.json" host="Sanath" sourcetype="_json" event_type="Failed SSH Login"
| stats count AS "Failed Attempts" dc(username) AS "Unique Users" by id.orig_h
| sort - "Unique Users"
```

---

## 4️⃣ Targeted User Analysis

```spl
source="ssh_logs_new.json" host="Sanath" sourcetype="_json" event_type="Failed SSH Login"
| stats count AS "Failed Attempts" values(username) AS "Targeted Users" by id.orig_h
| sort - "Failed Attempts"
```

---

## 5️⃣ Failed vs Successful Authentication

```spl
source="ssh_logs_new.json" host="Sanath" sourcetype="_json"
| stats count(eval(event_type="Failed SSH Login")) AS "Failed Logins"
        count(eval(event_type="Successful SSH Login")) AS "Successful Logins"
        by username
| sort - "Failed Logins"
```

---

## 6️⃣ Suspicious Authentication Detection

```spl
source="ssh_logs_new.json" host="Sanath" sourcetype="_json"
| stats count(eval(event_type="Failed SSH Login")) AS "Failed Logins"
        count(eval(event_type="Successful SSH Login")) AS "Successful Logins"
        by id.orig_h username
| eval "Total Attempts"='Failed Logins'+'Successful Logins'
| where 'Failed Logins' >= 20 AND 'Successful Logins' > 0
| sort - "Failed Logins"
```

---

## 7️⃣ Timeline Analysis

```spl
source="ssh_logs_new.json" host="Sanath" sourcetype="_json" event_type="Failed SSH Login"
| timechart span=1m count
```

> The current educational dataset contains highly concentrated timestamps, so the timeline may appear within a single time bucket.

---

# 🔥 Key Findings

The analysis identified:

```text
Total Events:                 3,600
Failed SSH Logins:              915
Successful SSH Logins:          918
Unauthenticated Connections:    858
```

### High-Failure Source/User Combinations

| Source IP | Username | Failed | Successful | Total |
|---|---|---:|---:|---:|
| 4.224.23.39 | alice | 33 | 18 | 51 |
| 105.236.211.106 | john.doe | 30 | 9 | 39 |
| 110.177.195.150 | test | 30 | 9 | 39 |
| 52.173.49.103 | backup | 30 | 18 | 48 |
| 74.165.131.224 | webmaster | 30 | 21 | 51 |
| 113.173.136.4 | dbadmin | 27 | 24 | 51 |
| 122.204.186.125 | svc_user | 27 | 21 | 48 |
| 135.176.100.83 | service | 27 | 15 | 42 |

These combinations were prioritized because they contained repeated authentication failures together with successful authentication.

---

# 🧠 SOC Analyst Investigation

A high number of failed logins alone does not prove malicious activity.

A SOC analyst should correlate:

```text
Source IP
    ↓
Target Username
    ↓
Failed Attempts
    ↓
Successful Authentication
    ↓
Timestamp
    ↓
Destination Host
    ↓
Post-Authentication Activity
```

If suspicious activity is confirmed, possible response actions include:

1. Investigate the source IP
2. Validate the targeted account
3. Review successful login timestamps
4. Check authentication methods
5. Review post-login activity
6. Investigate privilege escalation
7. Reset potentially compromised credentials
8. Terminate suspicious sessions
9. Block malicious infrastructure where appropriate
10. Escalate the incident

---

# 📸 Investigation Screenshots

Screenshots from the Splunk investigation will be included in the repository.

### Dashboard

![Dashboard](screenshots/01_dashboard_overview.png)

### Event Type Analysis

![Event Type Analysis](screenshots/02_event_type_analysis.png)

### Failed SSH Login Analysis

![Failed Login Analysis](screenshots/03_failed_login_analysis.png)

### Source IP Analysis

![Source IP Analysis](screenshots/04_source_ip_analysis.png)

### Targeted Users

![Targeted Users](screenshots/05_targeted_users.png)

### Suspicious Activity

![Suspicious Activity](screenshots/06_suspicious_activity.png)

---

# 📁 Project Structure

```text
splunk-ssh-log-analysis/
│
├── README.md
│
├── dashboard/
│   ├── ssh_authentication_dashboard.xml
│   └── README.md
│
├── spl_queries/
│   ├── 01_event_type_analysis.spl
│   ├── 02_failed_login_analysis.spl
│   ├── 03_source_ip_analysis.spl
│   ├── 04_targeted_users.spl
│   ├── 05_failed_vs_successful.spl
│   ├── 06_suspicious_activity.spl
│   └── 07_timeline_analysis.spl
│
├── screenshots/
│   ├── 01_dashboard_overview.png
│   ├── 02_event_type_analysis.png
│   ├── 03_failed_login_analysis.png
│   ├── 04_source_ip_analysis.png
│   ├── 05_targeted_users.png
│   └── 06_suspicious_activity.png
│
├── sample_data/
│   └── README.md
│
├── .gitignore
└── LICENSE
```

---

# 🎓 Skills Demonstrated

- Splunk Enterprise
- SPL Query Development
- SIEM Monitoring
- SSH Authentication Analysis
- Source IP Investigation
- Account Targeting Analysis
- Brute-Force Detection
- Event Correlation
- Security Dashboard Development
- SOC Investigation
- Security Event Triage
- Threat Detection

---

# 🚀 Future Improvements

- Real-time Splunk alerts
- Automated notable events
- GeoIP enrichment
- Threat intelligence integration
- Risk-based alerting
- MITRE ATT&CK mapping
- Automated response workflows
- Advanced authentication anomaly detection
- Production-style timestamp analysis

---

# ⚠️ Disclaimer

This project is intended for:

- Cybersecurity education
- SIEM training
- SOC analyst practice
- Blue Team learning
- Portfolio demonstration

The dataset used in this project is simulated/educational data.

Do not use these techniques against systems or accounts without proper authorization.

---

# 👨‍💻 Author

## Sanath Bansod

**Cybersecurity | VAPT | SOC | SIEM | Security Operations**

---

<p align="center">

### 🔐 Learn → Detect → Investigate → Respond

</p>
