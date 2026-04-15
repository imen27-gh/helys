"""
Helys SOC Decision Engine — FastAPI v3.1.0
==========================================
New in v3.1:
  - GET /alerts/{id}/pdf  → generates a per-alert PDF report on demand
  - Alert IDs added to every stored alert
  - Dashboard HTML served from GET /

Run:
    uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

import pickle
import numpy as np
import json
import uuid
import io
from collections import deque
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import Optional
from datetime import datetime

# ── ReportLab ──────────────────────────────────────────────────────────────
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.platypus import ListFlowable, ListItem

# ─── Load model artefacts ─────────────────────────────────────────────────────
with open("model_artefacts.pkl", "rb") as f:
    artefacts = pickle.load(f)

best_rf     = artefacts["best_rf"]
le_agent    = artefacts["le_agent"]
le_location = artefacts["le_location"]
HIPAA_RULES = artefacts["HIPAA_RULES"]

PRIORITY_MAP = {
    "ISOLATE_AND_ESCALATE":  "CRITICAL",
    "BLOCK_AND_INVESTIGATE": "HIGH",
    "REMEDIATE_CONFIG":      "MEDIUM",
    "INVESTIGATE":           "MEDIUM",
    "MONITOR_AND_LOG":       "LOW",
}
TTR_TARGETS = {"CRITICAL": 15, "HIGH": 60, "MEDIUM": 240, "LOW": 1440}

PRIORITY_COLORS = {
    "CRITICAL": colors.HexColor("#DC2626"),
    "HIGH":     colors.HexColor("#EA580C"),
    "MEDIUM":   colors.HexColor("#D97706"),
    "LOW":      colors.HexColor("#16A34A"),
}

# ─── In-memory alert store ────────────────────────────────────────────────────
alert_store: deque = deque(maxlen=1000)
alert_index: dict  = {}   # id → alert dict for O(1) lookup

# ─── Alert-specific playbook registry ────────────────────────────────────────
ALERT_PLAYBOOKS = {

    "brute_force": {
        "action": "BLOCK_AND_INVESTIGATE",
        "playbook": [
            "BLOCK — Immediately add the attacking source IP to the perimeter firewall deny list.",
            "AUDIT — Pull all SSH/RDP/web authentication logs for the targeted account(s) for the past 24 hours.",
            "CHECK — Determine if ANY login succeeded during the attack window. If yes, escalate to ISOLATE_AND_ESCALATE.",
            "RESET — Force an immediate password reset on all targeted accounts and enforce MFA enrollment.",
            "CORRELATE — Search SIEM for the same source IP attacking other agents in the environment.",
            "DOCUMENT — Log attacker IP, username targets, and TTPs in the threat intel platform and open a HIGH ticket.",
        ],
        "hipaa_override": "Technical Safeguards — Audit Controls [§164.312(b)]",
    },

    "privilege_escalation": {
        "action": "REMEDIATE_CONFIG",
        "playbook": [
            "REVIEW — Identify exactly which user account was escalated, by whom, and via which mechanism.",
            "REVERT — Remove the unauthorized privilege grant immediately (delete from Domain Admins / revert sudoers).",
            "AUDIT — Pull all commands and file accesses performed under the elevated privilege since escalation.",
            "CHECK ePHI — Determine if any electronic Protected Health Information was accessible from this privilege level.",
            "NOTIFY — If ePHI was accessible, alert the HIPAA Privacy Officer and initiate a breach risk assessment.",
            "HARDEN — Review and tighten privilege assignment policies; enforce least-privilege on the affected host.",
            "DOCUMENT — Record the full escalation chain, remediation steps, and outcome in the P1 incident ticket.",
        ],
        "hipaa_override": "Technical Safeguards — Access Control [§164.312(a)]",
    },

    "malware": {
        "action": "ISOLATE_AND_ESCALATE",
        "playbook": [
            "ISOLATE — Immediately cut the infected host from the network using EDR kill-switch or VLAN quarantine. Do NOT power off.",
            "PRESERVE — Take a live memory dump before any remediation to capture in-memory artefacts.",
            "IDENTIFY — Submit suspicious file hash to VirusTotal / MISP; determine malware family and MITRE ATT&CK techniques.",
            "TRACE — Identify the infection vector (phishing email, malicious download, lateral movement from another host).",
            "SCAN — Run EDR sweep on all hosts that communicated with the infected machine in the 48h prior to detection.",
            "CONTAIN — Block all C2 IPs/domains identified in malware analysis at the firewall and DNS sinkhole.",
            "NOTIFY — If the host processes ePHI, initiate the 60-day HIPAA breach notification clock immediately.",
            "REMEDIATE — Reimage or restore from a known-good snapshot only after forensics are complete.",
        ],
        "hipaa_override": "Technical Safeguards — Integrity [§164.312(c)]",
    },

    "ransomware": {
        "action": "ISOLATE_AND_ESCALATE",
        "playbook": [
            "ISOLATE IMMEDIATELY — Disconnect ALL affected hosts from the network. Every second spreads encryption.",
            "KILL SHARES — Disable SMB shares and mapped drives across the domain to prevent lateral spread.",
            "PRESERVE — Do NOT pay ransom. Take disk images of encrypted hosts for later decryption attempts.",
            "IDENTIFY STRAIN — Collect ransom note and sample encrypted file; submit to ID Ransomware (nomoreransom.org).",
            "ASSESS BACKUPS — Verify offline/immutable backup integrity. Check if backups were also encrypted.",
            "NOTIFY — Mandatory HIPAA breach notification if ePHI was on any encrypted host. Notify law enforcement (FBI IC3).",
            "RESTORE — Restore from clean backups only after full environment sweep confirms no persistence.",
            "POST-INCIDENT — Conduct root cause analysis; patch initial infection vector before reconnecting any host.",
        ],
        "hipaa_override": "Technical Safeguards — Integrity & Availability [§164.312(c)(d)]",
    },

    "port_scan": {
        "action": "MONITOR_AND_LOG",
        "playbook": [
            "LOG — Capture full netflow/packet capture for the scanning source IP.",
            "IDENTIFY — Determine if the scanning IP is internal (lateral movement) or external (attacker recon).",
            "BASELINE — Cross-reference with change management: is a new service legitimately listening on the new port?",
            "CORRELATE — Check if the scan is followed by exploitation attempts in the next 30-minute window.",
            "BLOCK IF EXTERNAL — If source is external and scan is aggressive, escalate to BLOCK_AND_INVESTIGATE.",
            "DOCUMENT — Record the scan pattern, targeted ports, and disposition (authorised / suppressed / escalated).",
        ],
        "hipaa_override": "Technical Safeguards — Transmission Security [§164.312(e)]",
    },

    "config_failure": {
        "action": "REMEDIATE_CONFIG",
        "playbook": [
            "IDENTIFY — Review the exact CIS benchmark control or SCA policy check that failed.",
            "ASSESS RISK — Determine if the misconfiguration exposes ePHI data or weakens a critical security control.",
            "REMEDIATE — Apply the specific configuration fix per the CIS hardening guide for this OS/application version.",
            "VERIFY — Re-run the SCA scan immediately after remediation to confirm the check now passes.",
            "UPDATE RISK REGISTER — Close the finding in the vulnerability tracker and update the HIPAA risk register.",
            "TRAIN — If the failure resulted from a human change, schedule a targeted security awareness refresher.",
            "DOCUMENT — Record finding, remediation steps, verification result, and responsible party in the audit log.",
        ],
        "hipaa_override": "Administrative Safeguards — Risk Management [§164.308(a)(1)]",
    },

    "sudo_abuse": {
        "action": "INVESTIGATE",
        "playbook": [
            "TRIAGE — Review which user attempted sudo, on which host, and what command was attempted.",
            "VERIFY INTENT — Contact the user or their manager to confirm whether the sudo attempt was legitimate.",
            "CHECK HISTORY — Pull the user's sudo history for the past 7 days to identify any pattern of abuse.",
            "CORRELATE — Check if the same user account shows other suspicious activity (after-hours login, large file access).",
            "ESCALATE IF NEEDED — If intent cannot be verified or a pattern is found, escalate to ISOLATE_AND_ESCALATE.",
            "DOCUMENT — Log investigation steps, user response, and conclusion in the ticket.",
        ],
        "hipaa_override": "Technical Safeguards — Access Control [§164.312(a)]",
    },

    "data_exfiltration": {
        "action": "ISOLATE_AND_ESCALATE",
        "playbook": [
            "BLOCK OUTBOUND — Immediately block all outbound connections from the affected host at the firewall.",
            "CAPTURE — Take a packet capture of any ongoing exfiltration traffic before blocking.",
            "QUANTIFY — Determine what data was transferred: volume, destination IP, protocol (HTTP/FTP/DNS tunnelling).",
            "CLASSIFY DATA — Identify if the exfiltrated data contains ePHI, PII, or credentials.",
            "NOTIFY — If ePHI was exfiltrated, initiate mandatory HIPAA breach notification (60-day clock starts now).",
            "TRACE SOURCE — Identify how the exfiltration was initiated (malware C2, insider, compromised credential).",
            "PRESERVE — Retain all logs and packet captures as evidence for forensic investigation and legal proceedings.",
        ],
        "hipaa_override": "Technical Safeguards — Transmission Security [§164.312(e)]",
    },

    "lateral_movement": {
        "action": "BLOCK_AND_INVESTIGATE",
        "playbook": [
            "MAP — Identify all hosts the attacker has touched; build a lateral movement map from authentication logs.",
            "ISOLATE PIVOT POINTS — Cut network segments between affected hosts to contain spread.",
            "ROTATE CREDENTIALS — Force password reset on ALL accounts that authenticated on any compromised host.",
            "CHECK PERSISTENCE — Scan all affected hosts for backdoors, new scheduled tasks, or new local admin accounts.",
            "HUNT — Use EDR telemetry to search for the same TTPs (Pass-the-Hash, Kerberoasting) across the environment.",
            "DOCUMENT — Build a full attack timeline from initial access to lateral movement for the post-incident report.",
        ],
        "hipaa_override": "Technical Safeguards — Access Control [§164.312(a)]",
    },

    "dos_attack": {
        "action": "BLOCK_AND_INVESTIGATE",
        "playbook": [
            "RATE LIMIT — Apply rate limiting at the edge firewall or load balancer for the attacking IP range.",
            "UPSTREAM — Contact ISP or CDN provider to apply upstream filtering if volumetric DDoS is confirmed.",
            "ASSESS IMPACT — Determine if any ePHI systems or clinical applications are experiencing downtime.",
            "FAILOVER — Activate business continuity plan if critical healthcare systems are unavailable.",
            "NOTIFY — If clinical operations are impacted, notify hospital leadership and consider HIPAA availability breach.",
            "DOCUMENT — Record attack timeline, peak volume, systems impacted, and mitigation steps taken.",
        ],
        "hipaa_override": "Technical Safeguards — Availability [§164.312(a)(2)(ii)]",
    },

    "insider_threat": {
        "action": "INVESTIGATE",
        "playbook": [
            "PRESERVE EVIDENCE — Do NOT alert the suspect. Silently capture all logs before any action.",
            "SCOPE — Determine what data or systems the user has accessed abnormally (volume, time, sensitivity).",
            "HR & LEGAL — Immediately loop in HR and Legal before taking any action against the user.",
            "MONITOR — Enable enhanced logging on the user's account and workstation covertly.",
            "REVOKE IF CRITICAL — If ePHI exfiltration is confirmed, revoke access immediately in coordination with HR.",
            "DOCUMENT — Maintain a strict chain of custody for all evidence for potential legal proceedings.",
        ],
        "hipaa_override": "Administrative Safeguards — Workforce Security [§164.308(a)(3)]",
    },

    "generic": {
        "action": "INVESTIGATE",
        "playbook": [
            "TRIAGE — Assess alert context: is this a known-good service, a misconfiguration, or a genuine threat?",
            "CORRELATE — Search SIEM for related alerts from the same agent in the past 1-hour window.",
            "BASELINE — Compare against historical alert patterns to determine if this is anomalous.",
            "ESCALATE IF NEEDED — If suspicious activity is confirmed, upgrade action to BLOCK or ISOLATE.",
            "DOCUMENT — Log investigation steps and final disposition in the ticket.",
        ],
        "hipaa_override": None,
    },
}

CATEGORY_RULES = [
    ("ransomware",           ["ransomware", "ransom note", "files encrypted", ".locked", ".encrypted"]),
    ("malware",              ["malware", "trojan", "virus", "rootkit", "spyware", "worm",
                               "suspicious process", "suspicious binary", "cryptominer"]),
    ("data_exfiltration",    ["exfiltration", "data exfil", "large upload", "unusual outbound",
                               "dns tunneling", "ftp upload"]),
    ("lateral_movement",     ["lateral movement", "pass the hash", "pass-the-hash", "kerberoasting",
                               "golden ticket", "mimikatz", "psexec", "remote exec"]),
    ("brute_force",          ["brute force", "multiple failed", "failed login", "failed logon",
                               "authentication failed", "authentication failure",
                               "maximum authentication", "missed the password",
                               "invalid user", "non existent user"]),
    ("privilege_escalation", ["privilege escalation", "domain admin", "added to admin",
                               "added to domain admins", "escalation", "suid"]),
    ("dos_attack",           ["denial of service", "dos attack", "ddos", "syn flood",
                               "udp flood", "icmp flood"]),
    ("insider_threat",       ["insider", "abnormal access", "mass download", "bulk download",
                               "unusual access pattern"]),
    ("sudo_abuse",           ["sudo", "sudoers", "failed attempts to run sudo",
                               "three failed attempts"]),
    ("port_scan",            ["listened ports", "netstat", "port scan", "nmap", "new port opened"]),
    ("config_failure",       ["sca", "cis", "benchmark", "apparmor", "password history",
                               "lockout threshold", "enforce password", "compliance", "hardening"]),
]

def detect_alert_category(description: str) -> str:
    desc = description.lower()
    for category, keywords in CATEGORY_RULES:
        if any(kw in desc for kw in keywords):
            return category
    return "generic"


# ─── Schema ───────────────────────────────────────────────────────────────────
class AlertInput(BaseModel):
    model_config = {"extra": "ignore"}

    rule_level:       int           = Field(..., ge=0)
    rule_id:          int           = Field(...)
    agent_name:       str           = Field(...)
    location:         str           = Field(...)
    has_srcip:        int           = Field(..., ge=0, le=1)
    rule_description: Optional[str] = Field(default="")
    hour:             Optional[int] = Field(default=None)
    day_of_week:      Optional[int] = Field(default=None)
    detection_ts:     Optional[str] = Field(default=None)

    @validator("rule_level", "rule_id", "has_srcip", pre=True)
    def coerce_to_int(cls, v):
        try:
            return int(float(str(v)))
        except (ValueError, TypeError):
            raise ValueError(f"Expected integer, got: {v}")


# ─── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(title="Helys SOC Decision Engine", version="3.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Core scoring ─────────────────────────────────────────────────────────────
def _score(alert: AlertInput) -> dict:
    hour        = alert.hour        if alert.hour        is not None else datetime.now().hour
    day_of_week = alert.day_of_week if alert.day_of_week is not None else datetime.now().weekday()
    det_ts      = alert.detection_ts or (datetime.utcnow().isoformat() + "Z")

    agent_enc    = le_agent.transform([alert.agent_name])[0]   if alert.agent_name in le_agent.classes_    else 0
    location_enc = le_location.transform([alert.location])[0]  if alert.location   in le_location.classes_ else 0
    is_after_hours = int(hour < 8 or hour >= 18)
    is_weekend     = int(day_of_week >= 5)

    features = np.array([[
        alert.rule_level, alert.rule_id,
        agent_enc, location_enc,
        alert.has_srcip, hour, day_of_week,
        is_after_hours, is_weekend
    ]])

    ml_action  = best_rf.predict(features)[0]
    confidence = round(float(max(best_rf.predict_proba(features)[0])) * 100, 1)

    desc            = alert.rule_description or ""
    category        = detect_alert_category(desc)
    playbook_entry  = ALERT_PLAYBOOKS[category]
    action          = playbook_entry["action"]
    playbook        = playbook_entry["playbook"]
    priority        = PRIORITY_MAP[action]

    hipaa_override  = playbook_entry.get("hipaa_override")
    desc_lower      = desc.lower()
    if hipaa_override:
        hipaa_safeguard = hipaa_override
        _, hipaa_guidance = next(
            ((s, g) for kw, (s, g) in HIPAA_RULES.items() if kw in desc_lower),
            (None, "Retain alert per §164.312(b) audit log requirements.")
        )
    else:
        hipaa_safeguard, hipaa_guidance = next(
            ((s, g) for kw, (s, g) in HIPAA_RULES.items() if kw in desc_lower),
            ("General — Document per Incident Response Plan",
             "Retain alert per §164.312(b) audit log requirements.")
        )

    return {
        "id":                  str(uuid.uuid4()),
        "timestamp":           datetime.utcnow().isoformat() + "Z",
        "detection_timestamp": det_ts,
        "response_timestamp":  datetime.utcnow().isoformat() + "Z",
        "agent_name":          alert.agent_name,
        "rule_level":          alert.rule_level,
        "rule_id":             alert.rule_id,
        "location":            alert.location,
        "has_srcip":           alert.has_srcip,
        "rule_description":    desc,
        "alert_category":      category,
        "decision": {
            "action":             action,
            "priority":           priority,
            "confidence_pct":     confidence,
            "ttr_target_minutes": TTR_TARGETS[priority],
            "automated":          action in ("ISOLATE_AND_ESCALATE", "BLOCK_AND_INVESTIGATE"),
            "ml_action":          ml_action,
        },
        "playbook": playbook,
        "hipaa": {
            "safeguard": hipaa_safeguard,
            "guidance":  hipaa_guidance,
        },
        "soar_hints": {
            "shuffle_workflow": f"wf_{action.lower()}",
            "alert_category":   category,
            "auto_containment": action == "ISOLATE_AND_ESCALATE",
            "firewall_block":   action == "BLOCK_AND_INVESTIGATE",
        },
    }


# ─── PDF generator ────────────────────────────────────────────────────────────
def _build_pdf(alert: dict) -> bytes:
    """
    Generates a professional A4 PDF incident report for a single alert.
    Returns raw bytes ready to stream to the browser.
    """
    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=18*mm, bottomMargin=18*mm,
    )

    W = A4[0] - 40*mm   # usable width

    decision = alert["decision"]
    hipaa    = alert["hipaa"]
    priority = decision["priority"]
    p_color  = PRIORITY_COLORS.get(priority, colors.grey)

    # ── Styles ────────────────────────────────────────────────────────────────
    base = getSampleStyleSheet()

    def style(name, **kw):
        s = ParagraphStyle(name, parent=base["Normal"], **kw)
        return s

    sTitle     = style("sTitle",    fontSize=20, leading=26, textColor=colors.HexColor("#0F172A"),
                       fontName="Helvetica-Bold", spaceAfter=2)
    sSubtitle  = style("sSub",      fontSize=9,  textColor=colors.HexColor("#64748B"),
                       fontName="Helvetica", spaceAfter=0)
    sSection   = style("sSec",      fontSize=11, leading=15, textColor=colors.HexColor("#1E293B"),
                       fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4)
    sBody      = style("sBody",     fontSize=9,  leading=13, textColor=colors.HexColor("#334155"),
                       fontName="Helvetica")
    sStep      = style("sStep",     fontSize=9,  leading=13, textColor=colors.HexColor("#1E293B"),
                       fontName="Helvetica", leftIndent=4)
    sFooter    = style("sFooter",   fontSize=7,  textColor=colors.HexColor("#94A3B8"),
                       fontName="Helvetica", alignment=TA_CENTER)
    sConfidential = style("sConf", fontSize=7,  textColor=colors.HexColor("#DC2626"),
                       fontName="Helvetica-Bold", alignment=TA_CENTER)

    story = []

    # ── Header bar (simulated with a table) ───────────────────────────────────
    header_data = [[
        Paragraph("<b>HELYS</b> SOC Decision Engine", style("hL", fontSize=10,
                  textColor=colors.white, fontName="Helvetica-Bold")),
        Paragraph("INCIDENT RESPONSE REPORT", style("hR", fontSize=8,
                  textColor=colors.HexColor("#CBD5E1"), fontName="Helvetica",
                  alignment=TA_RIGHT)),
    ]]
    header_tbl = Table(header_data, colWidths=[W*0.6, W*0.4])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), colors.HexColor("#0F172A")),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 6*mm))

    # ── Title + meta ──────────────────────────────────────────────────────────
    category_label = alert.get("alert_category", "generic").replace("_", " ").upper()
    story.append(Paragraph(f"Security Incident: {category_label}", sTitle))
    story.append(Paragraph(
        f"Report generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC  |  "
        f"Alert ID: {alert.get('id', 'N/A')}",
        sSubtitle
    ))
    story.append(Spacer(1, 4*mm))
    story.append(HRFlowable(width=W, thickness=1, color=colors.HexColor("#E2E8F0")))
    story.append(Spacer(1, 4*mm))

    # ── Priority badge + decision summary ─────────────────────────────────────
    badge_data = [[
        Paragraph(f"<b>{priority}</b>", style("badge", fontSize=14, textColor=colors.white,
                  fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(
            f"<b>Action:</b> {decision['action']}<br/>"
            f"<b>Confidence:</b> {decision['confidence_pct']}%<br/>"
            f"<b>TTR Target:</b> {decision['ttr_target_minutes']} minutes<br/>"
            f"<b>Automated:</b> {'Yes — SOAR will act' if decision['automated'] else 'No — analyst required'}",
            style("badgeR", fontSize=9, leading=14, textColor=colors.HexColor("#1E293B"),
                  fontName="Helvetica")
        ),
    ]]
    badge_tbl = Table(badge_data, colWidths=[30*mm, W - 30*mm])
    badge_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (0,0), p_color),
        ("BACKGROUND",   (1,0), (1,0), colors.HexColor("#F8FAFC")),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN",        (0,0), (0,0),  "CENTER"),
        ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("TOPPADDING",   (0,0), (-1,-1), 10),
        ("BOTTOMPADDING",(0,0), (-1,-1), 10),
        ("ROUNDEDCORNERS", (0,0), (-1,-1), [4, 4, 4, 4]),
        ("BOX",          (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
        ("INNERGRID",    (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(badge_tbl)
    story.append(Spacer(1, 5*mm))

    # ── Alert details table ────────────────────────────────────────────────────
    story.append(Paragraph("Alert Details", sSection))

    det_rows = [
        ["Field", "Value"],
        ["Rule Description", alert.get("rule_description", "N/A")],
        ["Agent / Host",     alert.get("agent_name", "N/A")],
        ["Rule Level",       str(alert.get("rule_level", "N/A"))],
        ["Rule ID",          str(alert.get("rule_id", "N/A"))],
        ["Log Source",       alert.get("location", "N/A")],
        ["External Source IP", "Yes" if alert.get("has_srcip") else "No"],
        ["Detection Time",   alert.get("detection_timestamp", "N/A")],
        ["Response Time",    alert.get("response_timestamp",  "N/A")],
    ]

    det_tbl = Table(
        [[Paragraph(str(r[0]), style("th", fontSize=8, fontName="Helvetica-Bold",
                    textColor=colors.HexColor("#475569"))),
          Paragraph(str(r[1]), sBody)] for r in det_rows],
        colWidths=[40*mm, W - 40*mm]
    )
    det_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#1E293B")),
        ("TEXTCOLOR",     (0,0), (-1,0),  colors.white),
        ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,0),  8),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("BOX",           (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
        ("INNERGRID",     (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    story.append(det_tbl)
    story.append(Spacer(1, 5*mm))

    # ── Playbook ──────────────────────────────────────────────────────────────
    story.append(Paragraph("Incident Response Playbook", sSection))
    story.append(Paragraph(
        f"The following steps are specific to a <b>{category_label}</b> incident "
        f"and must be executed in order:",
        sBody
    ))
    story.append(Spacer(1, 3*mm))

    step_rows = []
    for i, step in enumerate(alert.get("playbook", []), 1):
        # Split "ACTION — detail" format
        parts  = step.split(" — ", 1)
        action_label = parts[0].strip()
        detail       = parts[1].strip() if len(parts) > 1 else ""
        step_rows.append([
            Paragraph(f"<b>{i}</b>", style("stepNum", fontSize=10, fontName="Helvetica-Bold",
                      textColor=colors.white, alignment=TA_CENTER)),
            Paragraph(f"<b>{action_label}</b>", style("stepA", fontSize=9,
                      fontName="Helvetica-Bold", textColor=colors.HexColor("#0F172A"))),
            Paragraph(detail, sStep),
        ])

    step_tbl = Table(step_rows, colWidths=[8*mm, 35*mm, W - 43*mm])
    step_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (0,-1), p_color),
        ("BACKGROUND",    (1,0), (1,-1), colors.HexColor("#F1F5F9")),
        ("BACKGROUND",    (2,0), (2,-1), colors.white),
        ("ROWBACKGROUNDS",(1,0), (-1,-1), [colors.HexColor("#F1F5F9"), colors.HexColor("#F8FAFC")]),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("RIGHTPADDING",  (0,0), (-1,-1), 6),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("BOX",           (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
        ("INNERGRID",     (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(KeepTogether(step_tbl))
    story.append(Spacer(1, 5*mm))

    # ── HIPAA section ─────────────────────────────────────────────────────────
    story.append(Paragraph("HIPAA Compliance Context", sSection))

    hipaa_data = [
        [Paragraph("<b>Applicable Safeguard</b>", style("hh", fontSize=8,
                   fontName="Helvetica-Bold", textColor=colors.white)),
         Paragraph("<b>Required Guidance</b>", style("hh2", fontSize=8,
                   fontName="Helvetica-Bold", textColor=colors.white))],
        [Paragraph(hipaa["safeguard"], sBody),
         Paragraph(hipaa["guidance"],  sBody)],
    ]
    hipaa_tbl = Table(hipaa_data, colWidths=[W*0.45, W*0.55])
    hipaa_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#1E3A5F")),
        ("BACKGROUND",    (0,1), (-1,-1), colors.HexColor("#EFF6FF")),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("BOX",           (0,0), (-1,-1), 0.5, colors.HexColor("#BFDBFE")),
        ("INNERGRID",     (0,0), (-1,-1), 0.5, colors.HexColor("#BFDBFE")),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    story.append(hipaa_tbl)
    story.append(Spacer(1, 5*mm))

    # ── SOAR hints ────────────────────────────────────────────────────────────
    soar = alert.get("soar_hints", {})
    story.append(Paragraph("SOAR Automation Hints", sSection))
    soar_text = (
        f"<b>Shuffle Workflow:</b> {soar.get('shuffle_workflow', 'N/A')}&nbsp;&nbsp;"
        f"<b>Auto-Containment:</b> {'Triggered' if soar.get('auto_containment') else 'Not triggered'}&nbsp;&nbsp;"
        f"<b>Firewall Block:</b> {'Triggered' if soar.get('firewall_block') else 'Not triggered'}"
    )
    story.append(Paragraph(soar_text, sBody))
    story.append(Spacer(1, 8*mm))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(HRFlowable(width=W, thickness=0.5, color=colors.HexColor("#E2E8F0")))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph("CONFIDENTIAL — SOC USE ONLY", sConfidential))
    story.append(Paragraph(
        f"Generated by Helys SOC Decision Engine v3.1.0 · "
        f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        sFooter
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def dashboard():
    """Serves the SOC analyst dashboard."""
    return HTMLResponse(content=DASHBOARD_HTML)


@app.get("/health")
def health():
    return {"status": "ok", "model": "RandomForest", "version": "3.1.0",
            "categories": list(ALERT_PLAYBOOKS.keys())}


@app.post("/predict")
async def predict(request: Request):
    raw_body = await request.body()
    print("=" * 60)
    print("RAW BODY:", raw_body.decode())

    try:
        data = json.loads(raw_body)
    except json.JSONDecodeError as e:
        return JSONResponse(status_code=400, content={"error": f"Invalid JSON: {e}"})

    try:
        alert = AlertInput(**data)
    except Exception as e:
        return JSONResponse(status_code=422, content={"error": str(e), "received": data})

    result = _score(alert)
    alert_store.append(result)
    alert_index[result["id"]] = result
    print("RESPONSE:", json.dumps(result, indent=2))
    return result


@app.post("/predict/typed")
def predict_typed(alert: AlertInput):
    result = _score(alert)
    alert_store.append(result)
    alert_index[result["id"]] = result
    return result


@app.get("/alerts/latest")
def get_latest_alerts(since: str = None):
    alerts = list(alert_store)
    if since:
        try:
            alerts = [a for a in alerts if a.get("timestamp", "") > since]
        except Exception:
            pass
    return alerts


@app.get("/alerts/stats")
def alert_stats():
    alerts = list(alert_store)
    if not alerts:
        return {"total": 0}
    from collections import Counter
    priorities = Counter(a["decision"]["priority"]              for a in alerts)
    actions    = Counter(a["decision"]["action"]                for a in alerts)
    categories = Counter(a.get("alert_category", "generic")    for a in alerts)
    automated  = sum(1 for a in alerts if a["decision"]["automated"])
    return {
        "total":           len(alerts),
        "by_priority":     dict(priorities),
        "by_action":       dict(actions),
        "by_category":     dict(categories),
        "automation_rate": round(automated / len(alerts) * 100, 1),
        "latest_ts":       max((a.get("timestamp", "") for a in alerts), default=None),
    }


@app.get("/alerts/{alert_id}/pdf")
def download_alert_pdf(alert_id: str):
    """
    Generates and streams a PDF report for a single alert.
    Called when the analyst clicks 'Export PDF' in the dashboard.
    """
    alert = alert_index.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    pdf_bytes = _build_pdf(alert)
    category  = alert.get("alert_category", "alert").replace("_", "-")
    filename  = f"helys-incident-{category}-{alert_id[:8]}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.delete("/alerts/clear")
@app.get("/alerts/clear")
def clear_alerts():
    alert_store.clear()
    alert_index.clear()
    return {"status": "cleared"}


@app.get("/categories")
def list_categories():
    return {
        cat: {
            "action":   entry["action"],
            "priority": PRIORITY_MAP[entry["action"]],
            "steps":    len(entry["playbook"]),
        }
        for cat, entry in ALERT_PLAYBOOKS.items()
    }



