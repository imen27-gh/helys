# 🏥 Helys — AI-Powered Incident Response Recommendation System

> An AI-driven SOC decision engine that transforms raw **Wazuh SIEM alerts** into real-time, standardized, and HIPAA-aligned incident response recommendations.

---

## 📌 Overview

**Helys**  is a hybrid AI–SOC system that combines machine learning with cybersecurity operations to analyze Wazuh alerts and classify incidents into actionable response strategies.

It acts as an intelligent decision engine within a SOC, enabling automated, consistent, and faster incident response through AI-driven security workflows.
---

## 🚨 Problem Statement

Security analysts typically require **5 to 30 minutes per alert** to:
- Analyze logs
- Understand context
- Decide response actions

This leads to:
- ⏳ Slow incident response  
- ⚠️ Inconsistent decision-making  
- 🌙 No coverage outside working hours  
- 🏥 **HIPAA compliance risks**

---

## 💡 Solution

Helys automates this process by:
- Classifying alerts into **5 actionable response categories**
- Providing **standardized and explainable decisions**
- Mapping each alert to **HIPAA safeguards**
- Integrating directly into SOC workflows via API

---

## ⚡ Key Results

| Metric | Improvement |
|--------|------------|
| ⏱️ Decision Time | **< 5 ms** |
| 📉 MTTD | **−79%** (2.5 min vs 14.6 min) |
| 📉 MTTR | **−38%** (193 min vs 311 min) |
| 🤖 Automation Rate | **25% of alerts fully automated** |

---

## 📊 Dataset

- **Source**: Wazuh HIDS/SIEM alerts  
- **Size**: 179 real alerts  
- **Environment**: 5 monitored agents  
- **Features**:
  - `rule_level`, `rule_id`
  - `agent_name`, `location`
  - `has_srcip`
  - `hour`, `day_of_week`
  - `is_weekend`, `is_after_hours`

---

## 🧠 Machine Learning Model

- **Problem Type**: Multi-class classification  
- **Models Tested**:
  - Random Forest ✅ (selected)
  - Gradient Boosting  

### 🔥 Final Model: Random Forest (Tuned)
- F1 Score (weighted): **0.84**
- GridSearchCV optimization
- Stratified 5-fold cross-validation

---

## 🚀 Incident Response Classes

| Action | Description |
|--------|------------|
| 🔴 **ISOLATE_AND_ESCALATE** | Critical containment (privilege escalation, level ≥15) |
| 🟠 **BLOCK_AND_INVESTIGATE** | Block attacker + investigate (brute force, auth attacks) |
| 🔵 **REMEDIATE_CONFIG** | Fix compliance/config issues |
| ⚪ **INVESTIGATE** | Manual triage required |
| 🟢 **MONITOR_AND_LOG** | Low priority logging |

---

## 🏥 HIPAA Compliance Integration

Each alert is automatically mapped to **HIPAA Security Rule safeguards**:

- 🔐 Access Control   
- 📊 Audit Controls
- 🛡️ Integrity 
- 📉 Risk Management 
- 🌐 Transmission Security  

➡️ This ensures **audit-ready and compliant incident handling**

---

## 🏗️ System Architecture

### Components:
- 📡 **Wazuh SIEM** — Generates alerts  
- 🔀 **Shuffle SOAR** — Automation workflows  
- ⚡ **FastAPI** — ML inference API (<5ms)  
- 📋 **JSON Output** — Action + playbook + compliance  
- 🛡️ **SOAR Actions** — Firewall, EDR, AD, etc.  

---

## 📡 API Example

### Request


---

### 🔹 Example Request (cURL)

```bash
curl -X POST http:<your_ ip>:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "rule_level": 10,
    "rule_id": 5763,
    "agent_name": "agent1",
    "location": "journald",
    "has_srcip": 1
  }'
```
### Response
```bash
 {
  "decision": {
    "action": "BLOCK_AND_INVESTIGATE",
    "priority": "HIGH",
    "confidence_pct": 76.0,
    "ttr_target_minutes": 60,
    "automated": true
  },
  "playbook": [
    "Block source IP",
    "Review authentication logs"
  ],
  "hipaa": {
    "safeguard": "Audit Controls ",
    "guidance": "Block source IP and review logs"
  }
}
```


