# Linux Log Analysis, Automation, and SIEM Visualization

## 📌 Project Overview:

This project simulates a real-world Security Operations Center (SOC) workflow by analyzing Linux authentication logs to detect suspicious login activity.

### The project is divided into three stages:

- Manual log analysis

- Automated log analysis using Python

- SIEM-based investigation and visualization using Splunk Enterprise

The dataset used for this project was obtained from Linux authentication logs (LogHub).

## 🔍 Project Breakdown:

### 1️⃣ Manual Log Analysis

- Reviewed Linux authentication logs

- Identified failed login attempts and invalid users

- Detected suspicious IP activity targeting the root account

### 2️⃣ Python Automation

- Extracted log lines 200–500

#### Searched for:

- Failed password

- authentication failure

- invalid user

- user unknown

- Exported suspicious entries to CSV

### 3️⃣ SIEM Investigation (Splunk)

- Ingested logs into Splunk

- Queried authentication failures

- Used Events, Statistics, and Visualization views

- Identified repeated login attempts from specific IPs

## 🚨 Key Findings

- Repeated failed logins targeting root

- Burst-based authentication failures

- Behavior consistent with brute-force attack patterns

## 🛠️ Tools Used

- Python 3

- VS Code

- CSV

- Splunk Enterprise

## 🧠 Skills Demonstrated

- Log Analysis

- SOC Investigation Workflow

- Threat Detection

- Python Security Automation

- SIEM Querying & Visualization
  
## 👨‍💻 Author

**Ayush Yadav**  
Cybersecurity Enthusiast | SOC & Blue Team Focused  
