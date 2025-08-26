from datetime import datetime
from app import db
from app.utils.encryption import encrypt_data, decrypt_data

class Patient(db.Model):
    """Patient model with encrypted sensitive data"""
    __tablename__ = 'patients'
    
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    
    # Encrypted sensitive data
    ssn_hash = db.Column(db.String(255), nullable=True)  # Hashed SSN for verification
    phone_encrypted = db.Column(db.Text, nullable=True)
    email_encrypted = db.Column(db.Text, nullable=True)
    address_encrypted = db.Column(db.Text, nullable=True)
    
    # Medical information
    blood_type = db.Column(db.String(5), nullable=True)
    allergies = db.Column(db.Text, nullable=True)
    emergency_contact = db.Column(db.Text, nullable=True)
    insurance_info = db.Column(db.Text, nullable=True)
    
    # Relationships
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    records = db.relationship('Record', backref='patient', lazy='dynamic')
    appointments = db.relationship('Appointment', backref='patient', lazy='dynamic')
    
    # Metadata
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __init__(self, **kwargs):
        super(Patient, self).__init__(**kwargs)
        if 'ssn' in kwargs:
            self.set_ssn(kwargs['ssn'])
        if 'phone' in kwargs:
            self.set_phone(kwargs['phone'])
        if 'email' in kwargs:
            self.set_email(kwargs['email'])
        if 'address' in kwargs:
            self.set_address(kwargs['address'])
    
    def set_ssn(self, ssn):
        """Hash SSN for verification"""
        import hashlib
        self.ssn_hash = hashlib.sha256(ssn.encode()).hexdigest()
    
    def verify_ssn(self, ssn):
        """Verify SSN matches hash"""
        import hashlib
        return self.ssn_hash == hashlib.sha256(ssn.encode()).hexdigest()
    
    def set_phone(self, phone):
        """Encrypt phone number"""
        self.phone_encrypted = encrypt_data(phone)
    
    def get_phone(self):
        """Decrypt phone number"""
        return decrypt_data(self.phone_encrypted) if self.phone_encrypted else None
    
    def set_email(self, email):
        """Encrypt email"""
        self.email_encrypted = encrypt_data(email)
    
    def get_email(self):
        """Decrypt email"""
        return decrypt_data(self.email_encrypted) if self.email_encrypted else None
    
    def set_address(self, address):
        """Encrypt address"""
        self.address_encrypted = encrypt_data(address)
    
    def get_address(self):
        """Decrypt address"""
        return decrypt_data(self.address_encrypted) if self.address_encrypted else None
    
    def get_age(self):
        """Calculate patient age"""
        from datetime import date
        today = date.today()
        return today.year - self.date_of_birth.year - \
               ((today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day))
    
    def to_dict(self, include_sensitive=False):
        """Convert patient to dictionary"""
        data = {
            'id': self.id,
            'patient_id': self.patient_id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'date_of_birth': self.date_of_birth.isoformat(),
            'gender': self.gender,
            'blood_type': self.blood_type,
            'allergies': self.allergies,
            'emergency_contact': self.emergency_contact,
            'insurance_info': self.insurance_info,
            'doctor_id': self.doctor_id,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
        
        if include_sensitive:
            data.update({
                'phone': self.get_phone(),
                'email': self.get_email(),
                'address': self.get_address()
            })
        
        return data
    
    @staticmethod
    def generate_patient_id():
        """Generate unique patient ID"""
        import random
        import string
        while True:
            patient_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            if not Patient.query.filter_by(patient_id=patient_id).first():
                return patient_id
    
    @staticmethod
    def get_by_patient_id(patient_id):
        """Get patient by patient ID"""
        return Patient.query.filter_by(patient_id=patient_id).first()
    
    def __repr__(self):
        return f'<Patient {self.patient_id}: {self.first_name} {self.last_name}>'
