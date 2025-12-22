from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime

from app.database import get_db
from app.models import ZeroTrustLog
from app.schemas import ZeroTrustRequest, ZeroTrustDecision

router = APIRouter(prefix="/api/zt", tags=["Zero Trust"])


@router.post("/evaluate", response_model=ZeroTrustDecision)
def evaluate(req: ZeroTrustRequest, db: Session = Depends(get_db)):

    risk = (1 - req.device_trust_score) * 0.5 + req.behavior_risk_score * 0.5

    if risk < 0.3:
        decision, reason = "Allowed", "Low risk"
    elif risk < 0.6:
        decision, reason = "Allowed", "Moderate risk"
    else:
        decision, reason = "Denied", "High risk behavior detected"

    log = ZeroTrustLog(
        user_id=req.user_id,
        resource=req.resource,
        decision=decision,
        reason=reason
    )

    db.add(log)
    db.commit()

    return ZeroTrustDecision(
        decision=decision,
        reason=reason,
        confidence=0.9
    )
