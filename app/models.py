from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey ,float
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String, index=True)
    dst_ip = Column(String, index=True)
    protocol = Column(String, index=True)
    status = Column(String, index=True)  # "Allowed" or "Blocked"
    attack_type = Column(String, nullable=True, index=True)
    severity = Column(String, nullable=True, index=True)
    ml_confidence = Column(Float, nullable=True)  # ML model confidence score (0.0 to 1.0)
    
    # Relationship with BlockedIP (one-to-one)
    blocked_ip = relationship("BlockedIP", back_populates="traffic_log", uselist=False)


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip = Column(String, index=True)
    attack_type = Column(String, index=True)
    severity = Column(String, index=True)
    traffic_log_id = Column(Integer, ForeignKey('traffic_logs.id'))
    
    # Relationship with TrafficLog
    traffic_log = relationship("TrafficLog", back_populates="blocked_ip")
    decision = Column(String, default="Blocked")


class ZeroTrustLog(Base):
    __tablename__ = "zero_trust_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(String, index=True)
    resource = Column(String, index=True)
    decision = Column(String, index=True)  # "Allowed" or "Denied"
    reason = Column(String)
    
    # Add device_trust_score and behavior_risk_score for evaluation
    device_trust_score = Column(Integer, default=0)  # 0-100
    behavior_risk_score = Column(Integer, default=0)  # 0-100
