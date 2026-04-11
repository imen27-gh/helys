import pickle
import numpy as np
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import Optional
from datetime import datetime

# Charge le modèle
with open("model_artefacts.pkl", "rb") as f:
    artefacts = pickle.load(f)

best_rf          = artefacts["best_rf"]
le_agent         = artefacts["le_agent"]
le_location      = artefacts["le_location"]
HIPAA_RULES      = artefacts["HIPAA_RULES"]
ACTION_PLAYBOOKS = artefacts["ACTION_PLAYBOOKS"]

PRIORITY_MAP = {
    "ISOLATE_AND_ESCALATE":  "CRITICAL",
    "BLOCK_AND_INVESTIGATE": "HIGH",
    "REMEDIATE_CONFIG":      "MEDIUM",
    "INVESTIGATE":           "MEDIUM",
    "MONITOR_AND_LOG":       "LOW",
}
TTR_TARGETS = {"CRITICAL": 15, "HIGH": 60, "MEDIUM": 240, "LOW": 1440}


class AlertInput(BaseModel):
    rule_level:       int           = Field(..., ge=0, le=16)
    rule_id:          int           = Field(...)
    agent_name:       str           = Field(...)
    location:         str           = Field(...)
    has_srcip:        int           = Field(..., ge=0, le=1)
    rule_description: Optional[str] = Field("")
    hour:             Optional[int] = Field(None)
    day_of_week:      Optional[int] = Field(None)
    detection_ts:     Optional[str] = Field(None)

    @validator('rule_level', 'rule_id', 'has_srcip', pre=True)
    def coerce_to_int(cls, v):
        try:
            return int(float(str(v)))
        except (ValueError, TypeError):
            raise ValueError(f"Expected integer, got: {v}")


app = FastAPI(title="Helys SOC Decision Engine", version="2.0.0")


@app.get("/health")
def health():
    return {"status": "ok", "model": "RandomForest", "version": "2.0.0"}


@app.post("/predict")
async def predict(request: Request):
    # ── DEBUG : affiche le body brut reçu ────────────────────────────────
    raw_body = await request.body()
    print("=" * 50)
    print("RAW BODY FROM SHUFFLE:")
    print(raw_body.decode())
    print("HEADERS:")
    for k, v in request.headers.items():
        print(f"  {k}: {v}")
    print("=" * 50)

    # ── Parse le JSON manuellement ────────────────────────────────────────
    try:
        data = json.loads(raw_body)
    except json.JSONDecodeError as e:
        print("ERREUR JSON DECODE:", e)
        return JSONResponse(status_code=400, content={"error": f"Invalid JSON: {e}"})

    # ── Valide avec Pydantic ──────────────────────────────────────────────
    try:
        alert = AlertInput(**data)
    except Exception as e:
        print("ERREUR PYDANTIC:", e)
        return JSONResponse(status_code=422, content={"error": str(e), "received": data})

    # ── Inférence ─────────────────────────────────────────────────────────
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

    action     = best_rf.predict(features)[0]
    confidence = round(float(max(best_rf.predict_proba(features)[0])) * 100, 1)
    priority   = PRIORITY_MAP[action]

    desc_lower = (alert.rule_description or "").lower()
    hipaa_safeguard, hipaa_guidance = next(
        ((s, g) for kw, (s, g) in HIPAA_RULES.items() if kw in desc_lower),
        ("General", "Retain per §164.312(b).")
    )

    result = {
        "detection_timestamp": det_ts,
        "response_timestamp":  datetime.utcnow().isoformat() + "Z",
        "decision": {
            "action":             action,
            "priority":           priority,
            "confidence_pct":     confidence,
            "ttr_target_minutes": TTR_TARGETS[priority],
            "automated":          action in ("ISOLATE_AND_ESCALATE", "BLOCK_AND_INVESTIGATE"),
        },
        "playbook": ACTION_PLAYBOOKS[action],
        "hipaa": {
            "safeguard": hipaa_safeguard,
            "guidance":  hipaa_guidance,
        },
        "soar_hints": {
            "shuffle_workflow": f"wf_{action.lower()}",
            "auto_containment": action == "ISOLATE_AND_ESCALATE",
            "firewall_block":   action == "BLOCK_AND_INVESTIGATE",
        }
    }

    print("RESPONSE:", json.dumps(result, indent=2))
    return result
