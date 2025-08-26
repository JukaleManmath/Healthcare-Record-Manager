from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from app import db, bcrypt
from app.utils.encryption import encrypt_data, decrypt_data

class User(db.Model):
    """User model with role-based access control"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='patient')
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    patients = db.relationship('Patient', backref='assigned_doctor', lazy='dynamic')
    records_created = db.relationship('Record', backref='created_by', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')
    
    # Role constants
    ROLES = {
        'admin': 'Administrator',
        'doctor': 'Doctor',
        'nurse': 'Nurse',
        'patient': 'Patient'
    }
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if 'password' in kwargs:
            self.set_password(kwargs['password'])
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        """Check if password matches hash"""
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def has_role(self, role):
        """Check if user has specific role"""
        return self.role == role
    
    def has_permission(self, permission):
        """Check if user has specific permission"""
        permissions = {
            'admin': ['read', 'write', 'delete', 'admin'],
            'doctor': ['read', 'write'],
            'nurse': ['read', 'write'],
            'patient': ['read']
        }
        return permission in permissions.get(self.role, [])
    
    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'role': self.role,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    @staticmethod
    def get_by_username(username):
        """Get user by username"""
        return User.query.filter_by(username=username).first()
    
    @staticmethod
    def get_by_email(email):
        """Get user by email"""
        return User.query.filter_by(email=email).first()
    
    def __repr__(self):
        return f'<User {self.username}>'
