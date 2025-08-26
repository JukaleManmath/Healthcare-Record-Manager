from datetime import datetime, timedelta
from app import db

class Appointment(db.Model):
    """Appointment model for patient scheduling"""
    __tablename__ = 'appointments'
    
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Appointment details
    appointment_type = db.Column(db.String(50), nullable=False)  # 'consultation', 'follow_up', 'emergency', etc.
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Scheduling
    scheduled_date = db.Column(db.DateTime, nullable=False)
    duration_minutes = db.Column(db.Integer, default=30)
    end_time = db.Column(db.DateTime, nullable=False)
    
    # Status
    status = db.Column(db.String(20), default='scheduled')  # 'scheduled', 'confirmed', 'in_progress', 'completed', 'cancelled', 'no_show'
    
    # Location and notes
    location = db.Column(db.String(100), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    confirmed_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    cancelled_at = db.Column(db.DateTime, nullable=True)
    
    # Reminders
    reminder_sent = db.Column(db.Boolean, default=False)
    reminder_sent_at = db.Column(db.DateTime, nullable=True)
    
    def __init__(self, **kwargs):
        super(Appointment, self).__init__(**kwargs)
        if 'scheduled_date' in kwargs and 'duration_minutes' in kwargs:
            self.end_time = kwargs['scheduled_date'] + timedelta(minutes=kwargs['duration_minutes'])
    
    def confirm(self):
        """Confirm the appointment"""
        self.status = 'confirmed'
        self.confirmed_at = datetime.utcnow()
    
    def start(self):
        """Start the appointment"""
        self.status = 'in_progress'
    
    def complete(self):
        """Complete the appointment"""
        self.status = 'completed'
        self.completed_at = datetime.utcnow()
    
    def cancel(self, reason=None):
        """Cancel the appointment"""
        self.status = 'cancelled'
        self.cancelled_at = datetime.utcnow()
        if reason:
            self.notes = f"Cancelled: {reason}\n\n{self.notes or ''}"
    
    def mark_no_show(self):
        """Mark appointment as no-show"""
        self.status = 'no_show'
        self.notes = f"No-show\n\n{self.notes or ''}"
    
    def send_reminder(self):
        """Mark reminder as sent"""
        self.reminder_sent = True
        self.reminder_sent_at = datetime.utcnow()
    
    def is_overdue(self):
        """Check if appointment is overdue"""
        return self.status == 'scheduled' and datetime.utcnow() > self.end_time
    
    def is_upcoming(self, hours=24):
        """Check if appointment is upcoming within specified hours"""
        now = datetime.utcnow()
        return (self.status == 'scheduled' and 
                now < self.scheduled_date < now + timedelta(hours=hours))
    
    def to_dict(self):
        """Convert appointment to dictionary"""
        return {
            'id': self.id,
            'appointment_id': self.appointment_id,
            'patient_id': self.patient_id,
            'doctor_id': self.doctor_id,
            'appointment_type': self.appointment_type,
            'title': self.title,
            'description': self.description,
            'scheduled_date': self.scheduled_date.isoformat(),
            'duration_minutes': self.duration_minutes,
            'end_time': self.end_time.isoformat(),
            'status': self.status,
            'location': self.location,
            'notes': self.notes,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'confirmed_at': self.confirmed_at.isoformat() if self.confirmed_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'cancelled_at': self.cancelled_at.isoformat() if self.cancelled_at else None,
            'reminder_sent': self.reminder_sent,
            'reminder_sent_at': self.reminder_sent_at.isoformat() if self.reminder_sent_at else None
        }
    
    @staticmethod
    def generate_appointment_id():
        """Generate unique appointment ID"""
        import random
        import string
        while True:
            appointment_id = 'APT' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            if not Appointment.query.filter_by(appointment_id=appointment_id).first():
                return appointment_id
    
    @staticmethod
    def get_by_appointment_id(appointment_id):
        """Get appointment by appointment ID"""
        return Appointment.query.filter_by(appointment_id=appointment_id).first()
    
    @staticmethod
    def get_doctor_appointments(doctor_id, start_date=None, end_date=None, status=None):
        """Get appointments for a specific doctor"""
        query = Appointment.query.filter_by(doctor_id=doctor_id)
        if start_date:
            query = query.filter(Appointment.scheduled_date >= start_date)
        if end_date:
            query = query.filter(Appointment.scheduled_date <= end_date)
        if status:
            query = query.filter_by(status=status)
        return query.order_by(Appointment.scheduled_date).all()
    
    @staticmethod
    def get_patient_appointments(patient_id, start_date=None, end_date=None, status=None):
        """Get appointments for a specific patient"""
        query = Appointment.query.filter_by(patient_id=patient_id)
        if start_date:
            query = query.filter(Appointment.scheduled_date >= start_date)
        if end_date:
            query = query.filter(Appointment.scheduled_date <= end_date)
        if status:
            query = query.filter_by(status=status)
        return query.order_by(Appointment.scheduled_date).all()
    
    @staticmethod
    def get_upcoming_appointments(hours=24):
        """Get upcoming appointments within specified hours"""
        now = datetime.utcnow()
        end_time = now + timedelta(hours=hours)
        return Appointment.query.filter(
            Appointment.status == 'scheduled',
            Appointment.scheduled_date >= now,
            Appointment.scheduled_date <= end_time
        ).order_by(Appointment.scheduled_date).all()
    
    @staticmethod
    def get_overdue_appointments():
        """Get overdue appointments"""
        return Appointment.query.filter(
            Appointment.status == 'scheduled',
            Appointment.end_time < datetime.utcnow()
        ).order_by(Appointment.scheduled_date).all()
    
    @staticmethod
    def check_availability(doctor_id, start_time, end_time, exclude_appointment_id=None):
        """Check if doctor is available during specified time"""
        query = Appointment.query.filter(
            Appointment.doctor_id == doctor_id,
            Appointment.status.in_(['scheduled', 'confirmed']),
            db.or_(
                db.and_(
                    Appointment.scheduled_date < end_time,
                    Appointment.end_time > start_time
                )
            )
        )
        
        if exclude_appointment_id:
            query = query.filter(Appointment.appointment_id != exclude_appointment_id)
        
        return query.count() == 0
    
    def __repr__(self):
        return f'<Appointment {self.appointment_id}: {self.title} on {self.scheduled_date}>'
