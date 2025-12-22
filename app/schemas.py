from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"

class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class Status(str, Enum):
    ALLOWED = "Allowed"
    BLOCKED = "Blocked"

class Decision(str, Enum):
    ALLOWED = "Allowed"
    DENIED = "Denied"

class TrafficSample(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: Protocol = Protocol.TCP

class TrafficPrediction(BaseModel):
    is_attack: bool = Field(..., example=True)
    attack_type: Optional[str] = Field(None, example="DDoS")
    severity: Optional[Severity] = Field(None, example="Critical")
    status: Status = Field(..., example="Blocked")
    ml_confidence: Optional[float] = Field(None, ge=0.0, le=1.0, example=0.95)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_encoders = {
            Severity: lambda v: v.value,
            Status: lambda v: v.value,
            datetime: lambda v: v.isoformat()
        }


class TrafficLogResponse(BaseModel):
    id: int
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    status: str
    attack_type: Optional[str] = None
    severity: Optional[str] = None
    ml_confidence: Optional[float] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        orm_mode = True

class ZeroTrustRequest(BaseModel):
    user_id: str = Field(..., example="user123")
    resource: str = Field(..., example="/api/sensitive-data")
    device_trust_score: float = Field(..., ge=0, le=100, example=85.5)
    behavior_risk_score: float = Field(..., ge=0, le=100, example=25.0)
    
    @validator('device_trust_score', 'behavior_risk_score')
    def validate_scores(cls, v):
        if not 0 <= v <= 100:
            raise ValueError('Score must be between 0 and 100')
        return v

class ZeroTrustDecision(BaseModel):
    decision: Decision = Field(..., example="Allowed")
    reason: str = Field(..., example="Low risk")
    confidence: float = Field(..., ge=0.0, le=1.0, example=0.95)
    
    class Config:
        json_encoders = {
            Decision: lambda v: v.value
        }
