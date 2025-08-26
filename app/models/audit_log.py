from datetime import datetime
from app import db

class AuditLog(db.Model):
    """Audit log model for compliance and security tracking"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    session_id = db.Column(db.String(100), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    user_agent = db.Column(db.Text, nullable=True)
    
    # Action details
    action = db.Column(db.String(100), nullable=False)  # 'login', 'logout', 'create', 'read', 'update', 'delete'
    resource_type = db.Column(db.String(50), nullable=True)  # 'user', 'patient', 'record', etc.
    resource_id = db.Column(db.String(50), nullable=True)
    
    # Request details
    method = db.Column(db.String(10), nullable=True)  # GET, POST, PUT, DELETE
    endpoint = db.Column(db.String(200), nullable=True)
    status_code = db.Column(db.Integer, nullable=True)
    
    # Data changes
    old_values = db.Column(db.Text, nullable=True)  # JSON of old values
    new_values = db.Column(db.Text, nullable=True)  # JSON of new values
    
    # Metadata
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    duration_ms = db.Column(db.Integer, nullable=True)  # Request duration in milliseconds
    
    # Security flags
    is_suspicious = db.Column(db.Boolean, default=False)
    risk_level = db.Column(db.String(20), default='low')  # 'low', 'medium', 'high', 'critical'
    
    def __init__(self, **kwargs):
        super(AuditLog, self).__init__(**kwargs)
        if 'old_values' in kwargs and isinstance(kwargs['old_values'], dict):
            self.old_values = self._serialize_data(kwargs['old_values'])
        if 'new_values' in kwargs and isinstance(kwargs['new_values'], dict):
            self.new_values = self._serialize_data(kwargs['new_values'])
    
    def _serialize_data(self, data):
        """Serialize data to JSON string"""
        import json
        return json.dumps(data, default=str)
    
    def _deserialize_data(self, data_str):
        """Deserialize JSON string to data"""
        import json
        if data_str:
            return json.loads(data_str)
        return None
    
    def get_old_values(self):
        """Get deserialized old values"""
        return self._deserialize_data(self.old_values)
    
    def get_new_values(self):
        """Get deserialized new values"""
        return self._deserialize_data(self.new_values)
    
    def to_dict(self):
        """Convert audit log to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'method': self.method,
            'endpoint': self.endpoint,
            'status_code': self.status_code,
            'old_values': self.get_old_values(),
            'new_values': self.get_new_values(),
            'timestamp': self.timestamp.isoformat(),
            'duration_ms': self.duration_ms,
            'is_suspicious': self.is_suspicious,
            'risk_level': self.risk_level
        }
    
    @staticmethod
    def log_action(user_id=None, session_id=None, ip_address=None, user_agent=None,
                   action=None, resource_type=None, resource_id=None, method=None,
                   endpoint=None, status_code=None, old_values=None, new_values=None,
                   duration_ms=None):
        """Create a new audit log entry"""
        log = AuditLog(
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            old_values=old_values,
            new_values=new_values,
            duration_ms=duration_ms
        )
        
        # Analyze risk level
        log.analyze_risk()
        
        db.session.add(log)
        db.session.commit()
        return log
    
    def analyze_risk(self):
        """Analyze and set risk level for this audit log"""
        risk_score = 0
        
        # High-risk actions
        high_risk_actions = ['delete', 'export', 'bulk_update', 'password_change']
        if self.action in high_risk_actions:
            risk_score += 3
        
        # Suspicious patterns
        if self.status_code == 403:  # Forbidden
            risk_score += 2
        if self.status_code == 401:  # Unauthorized
            risk_score += 1
        if self.status_code >= 500:  # Server errors
            risk_score += 1
        
        # Multiple failed attempts
        if self.action == 'login' and self.status_code != 200:
            risk_score += 2
        
        # Set risk level
        if risk_score >= 5:
            self.risk_level = 'critical'
            self.is_suspicious = True
        elif risk_score >= 3:
            self.risk_level = 'high'
            self.is_suspicious = True
        elif risk_score >= 2:
            self.risk_level = 'medium'
        else:
            self.risk_level = 'low'
    
    @staticmethod
    def get_user_activity(user_id, start_date=None, end_date=None):
        """Get activity logs for a specific user"""
        query = AuditLog.query.filter_by(user_id=user_id)
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        return query.order_by(AuditLog.timestamp.desc()).all()
    
    @staticmethod
    def get_suspicious_activity(start_date=None, end_date=None):
        """Get suspicious activity logs"""
        query = AuditLog.query.filter_by(is_suspicious=True)
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        return query.order_by(AuditLog.timestamp.desc()).all()
    
    @staticmethod
    def get_resource_history(resource_type, resource_id):
        """Get audit history for a specific resource"""
        return AuditLog.query.filter_by(
            resource_type=resource_type,
            resource_id=resource_id
        ).order_by(AuditLog.timestamp.desc()).all()
    
    def __repr__(self):
        return f'<AuditLog {self.action} on {self.resource_type}:{self.resource_id} by user {self.user_id}>'
