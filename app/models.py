from app import db
from datetime import datetime
import uuid

class ScanTask(db.Model):
    """扫描任务模型"""
    __tablename__ = 'scan_tasks'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    skill_name = db.Column(db.String(200), nullable=False)
    skill_version = db.Column(db.String(50), default='unknown')
    file_path = db.Column(db.String(500))
    task_status = db.Column(db.String(20), default='pending')  # pending, queued, running, completed, failed
    risk_level = db.Column(db.String(20), default='unknown')  # safe, warning, dangerous, high-risk, unknown
    risk_score = db.Column(db.Integer, default=0)
    risk_tags = db.Column(db.String(500))  # JSON string of risk tags
    threat_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    submitted_by = db.Column(db.String(100), default='anonymous')
    report_path = db.Column(db.String(500))
    scan_options = db.Column(db.String(200), default='{}')
    progress = db.Column(db.Integer, default=0)
    content_hash = db.Column(db.String(64))
    
    # Relationships
    threats = db.relationship('ThreatFinding', backref='task', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'skill_name': self.skill_name,
            'skill_version': self.skill_version,
            'task_status': self.task_status,
            'risk_level': self.risk_level,
            'risk_score': self.risk_score,
            'risk_tags': self.risk_tags,
            'threat_count': self.threat_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'submitted_by': self.submitted_by,
            'scan_options': self.scan_options,
            'progress': self.progress,
            'content_hash': self.content_hash
        }

class ThreatFinding(db.Model):
    """威胁发现模型"""
    __tablename__ = 'threat_findings'
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.String(36), db.ForeignKey('scan_tasks.id'), nullable=False)
    threat_type = db.Column(db.String(50), nullable=False)  # malicious_url, data_exfiltration, etc.
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    evidence = db.Column(db.Text)
    file_location = db.Column(db.String(500))
    line_number = db.Column(db.Integer)
    detection_method = db.Column(db.String(50))  # static_analysis, signature_matching, llm_analysis, sandbox
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'task_id': self.task_id,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'evidence': self.evidence,
            'file_location': self.file_location,
            'line_number': self.line_number,
            'detection_method': self.detection_method,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class MaliciousDomain(db.Model):
    """恶意域名模型"""
    __tablename__ = 'malicious_domains'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False, unique=True)
    source = db.Column(db.String(100), default='manual')
    severity = db.Column(db.String(20), default='high')
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'source': self.source,
            'severity': self.severity,
            'description': self.description,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class TrustedSkill(db.Model):
    """可信Skill模型"""
    __tablename__ = 'trusted_skills'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    version = db.Column(db.String(50), default='1.0.0')
    description = db.Column(db.Text)
    author = db.Column(db.String(200))
    source = db.Column(db.String(50), default='community')  # official, verified, community
    risk_level = db.Column(db.String(20), default='safe')  # safe, warning, dangerous
    download_count = db.Column(db.Integer, default=0)
    rating = db.Column(db.Float, default=5.0)
    tags = db.Column(db.String(300))
    is_blacklisted = db.Column(db.Boolean, default=False)
    blacklist_reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': self.author,
            'source': self.source,
            'risk_level': self.risk_level,
            'download_count': self.download_count,
            'rating': self.rating,
            'tags': self.tags,
            'is_blacklisted': self.is_blacklisted,
            'blacklist_reason': self.blacklist_reason,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class ThreatRule(db.Model):
    """威胁检测规则模型"""
    __tablename__ = 'threat_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    rule_type = db.Column(db.String(50), nullable=False)
    pattern = db.Column(db.String(500), nullable=False)
    severity = db.Column(db.String(20), default='medium')
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'rule_type': self.rule_type,
            'pattern': self.pattern,
            'severity': self.severity,
            'description': self.description,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class ScanReport(db.Model):
    """扫描报告模型"""
    __tablename__ = 'scan_reports'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    task_id = db.Column(db.String(36), db.ForeignKey('scan_tasks.id'), nullable=False)
    report_data = db.Column(db.Text)  # JSON string of full report
    summary = db.Column(db.Text)
    recommendations = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'task_id': self.task_id,
            'summary': self.summary,
            'recommendations': self.recommendations,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
