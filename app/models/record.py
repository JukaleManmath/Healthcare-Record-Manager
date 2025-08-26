from datetime import datetime
from app import db
from app.utils.encryption import encrypt_data, decrypt_data

class Record(db.Model):
    """Medical record model with encrypted content"""
    __tablename__ = 'records'
    
    id = db.Column(db.Integer, primary_key=True)
    record_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Record metadata
    record_type = db.Column(db.String(50), nullable=False)  # 'consultation', 'lab_result', 'prescription', etc.
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Encrypted content
    content_encrypted = db.Column(db.Text, nullable=False)
    attachments_encrypted = db.Column(db.Text, nullable=True)  # JSON of encrypted file paths
    
    # Status and workflow
    status = db.Column(db.String(20), default='draft')  # 'draft', 'reviewed', 'approved', 'archived'
    priority = db.Column(db.String(20), default='normal')  # 'low', 'normal', 'high', 'urgent'
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    
    # Versioning
    version = db.Column(db.Integer, default=1)
    parent_record_id = db.Column(db.Integer, db.ForeignKey('records.id'), nullable=True)
    
    # Relationships
    parent_record = db.relationship('Record', remote_side=[id], backref='versions')
    
    def __init__(self, **kwargs):
        super(Record, self).__init__(**kwargs)
        if 'content' in kwargs:
            self.set_content(kwargs['content'])
        if 'attachments' in kwargs:
            self.set_attachments(kwargs['attachments'])
    
    def set_content(self, content):
        """Encrypt record content"""
        self.content_encrypted = encrypt_data(content)
    
    def get_content(self):
        """Decrypt record content"""
        return decrypt_data(self.content_encrypted)
    
    def set_attachments(self, attachments):
        """Encrypt attachments metadata"""
        import json
        if attachments:
            self.attachments_encrypted = encrypt_data(json.dumps(attachments))
    
    def get_attachments(self):
        """Decrypt attachments metadata"""
        import json
        if self.attachments_encrypted:
            return json.loads(decrypt_data(self.attachments_encrypted))
        return []
    
    def create_version(self, new_content, new_attachments=None):
        """Create a new version of this record"""
        new_record = Record(
            record_id=self.record_id,
            patient_id=self.patient_id,
            created_by_id=self.created_by_id,
            record_type=self.record_type,
            title=self.title,
            description=self.description,
            content=new_content,
            attachments=new_attachments,
            status='draft',
            priority=self.priority,
            parent_record_id=self.id,
            version=self.version + 1
        )
        return new_record
    
    def approve(self, approved_by_id):
        """Approve the record"""
        self.status = 'approved'
        self.approved_at = datetime.utcnow()
        self.reviewed_at = datetime.utcnow()
    
    def review(self, reviewed_by_id):
        """Mark record as reviewed"""
        self.status = 'reviewed'
        self.reviewed_at = datetime.utcnow()
    
    def archive(self):
        """Archive the record"""
        self.status = 'archived'
    
    def to_dict(self, include_content=True):
        """Convert record to dictionary"""
        data = {
            'id': self.id,
            'record_id': self.record_id,
            'patient_id': self.patient_id,
            'created_by_id': self.created_by_id,
            'record_type': self.record_type,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'priority': self.priority,
            'version': self.version,
            'parent_record_id': self.parent_record_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None
        }
        
        if include_content:
            data['content'] = self.get_content()
            data['attachments'] = self.get_attachments()
        
        return data
    
    @staticmethod
    def generate_record_id():
        """Generate unique record ID"""
        import random
        import string
        while True:
            record_id = 'REC' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            if not Record.query.filter_by(record_id=record_id).first():
                return record_id
    
    @staticmethod
    def get_by_record_id(record_id):
        """Get record by record ID"""
        return Record.query.filter_by(record_id=record_id).first()
    
    @staticmethod
    def get_patient_records(patient_id, record_type=None, status=None):
        """Get records for a specific patient"""
        query = Record.query.filter_by(patient_id=patient_id)
        if record_type:
            query = query.filter_by(record_type=record_type)
        if status:
            query = query.filter_by(status=status)
        return query.order_by(Record.created_at.desc()).all()
    
    def __repr__(self):
        return f'<Record {self.record_id}: {self.title}>'
