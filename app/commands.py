import click
from flask.cli import with_appcontext
from app import db
from app.models import User, Patient, Record
from app.utils.encryption import generate_encryption_key
import structlog

logger = structlog.get_logger()

@click.command('init-db')
@with_appcontext
def init_db():
    """Initialize the database."""
    try:
        db.create_all()
        click.echo('Database initialized successfully.')
        logger.info("Database initialized")
    except Exception as e:
        click.echo(f'Error initializing database: {e}')
        logger.error("Database initialization failed", error=str(e))

@click.command('create-admin')
@click.option('--username', prompt='Admin username', help='Admin username')
@click.option('--email', prompt='Admin email', help='Admin email')
@click.option('--password', prompt='Admin password', hide_input=True, confirmation_prompt=True, help='Admin password')
@click.option('--first-name', prompt='First name', help='First name')
@click.option('--last-name', prompt='Last name', help='Last name')
@with_appcontext
def create_admin(username, email, password, first_name, last_name):
    """Create an admin user."""
    try:
        # Check if admin already exists
        existing_admin = User.query.filter_by(role='admin').first()
        if existing_admin:
            click.echo('Admin user already exists.')
            return
        
        # Create admin user
        admin = User(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            role='admin',
            is_active=True,
            is_verified=True
        )
        
        db.session.add(admin)
        db.session.commit()
        
        click.echo(f'Admin user {username} created successfully.')
        logger.info("Admin user created", username=username)
        
    except Exception as e:
        click.echo(f'Error creating admin user: {e}')
        logger.error("Admin user creation failed", error=str(e))
        db.session.rollback()

@click.command('seed-data')
@with_appcontext
def seed_data():
    """Seed the database with sample data."""
    try:
        click.echo('Seeding database with sample data...')
        
        # Create sample users
        users_data = [
            {
                'username': 'dr_smith',
                'email': 'dr.smith@healthcare.com',
                'password': 'password123',
                'first_name': 'John',
                'last_name': 'Smith',
                'role': 'doctor'
            },
            {
                'username': 'dr_johnson',
                'email': 'dr.johnson@healthcare.com',
                'password': 'password123',
                'first_name': 'Sarah',
                'last_name': 'Johnson',
                'role': 'doctor'
            },
            {
                'username': 'nurse_wilson',
                'email': 'nurse.wilson@healthcare.com',
                'password': 'password123',
                'first_name': 'Michael',
                'last_name': 'Wilson',
                'role': 'nurse'
            },
            {
                'username': 'patient_doe',
                'email': 'john.doe@email.com',
                'password': 'password123',
                'first_name': 'John',
                'last_name': 'Doe',
                'role': 'patient'
            }
        ]
        
        created_users = []
        for user_data in users_data:
            # Check if user already exists
            existing_user = User.query.filter_by(username=user_data['username']).first()
            if not existing_user:
                user = User(**user_data)
                db.session.add(user)
                created_users.append(user)
        
        db.session.commit()
        click.echo(f'Created {len(created_users)} users.')
        
        # Create sample patients
        patients_data = [
            {
                'first_name': 'Alice',
                'last_name': 'Johnson',
                'date_of_birth': '1985-03-15',
                'gender': 'Female',
                'phone': '+1-555-0123',
                'email': 'alice.johnson@email.com',
                'address': '123 Main St, Anytown, USA',
                'blood_type': 'A+',
                'allergies': 'Penicillin',
                'emergency_contact': 'Bob Johnson, +1-555-0124'
            },
            {
                'first_name': 'Robert',
                'last_name': 'Brown',
                'date_of_birth': '1978-07-22',
                'gender': 'Male',
                'phone': '+1-555-0125',
                'email': 'robert.brown@email.com',
                'address': '456 Oak Ave, Somewhere, USA',
                'blood_type': 'O-',
                'allergies': 'None',
                'emergency_contact': 'Mary Brown, +1-555-0126'
            },
            {
                'first_name': 'Emily',
                'last_name': 'Davis',
                'date_of_birth': '1992-11-08',
                'gender': 'Female',
                'phone': '+1-555-0127',
                'email': 'emily.davis@email.com',
                'address': '789 Pine Rd, Elsewhere, USA',
                'blood_type': 'B+',
                'allergies': 'Shellfish',
                'emergency_contact': 'David Davis, +1-555-0128'
            }
        ]
        
        created_patients = []
        for i, patient_data in enumerate(patients_data):
            # Check if patient already exists
            existing_patient = Patient.query.filter_by(
                first_name=patient_data['first_name'],
                last_name=patient_data['last_name']
            ).first()
            
            if not existing_patient:
                patient = Patient(
                    patient_id=Patient.generate_patient_id(),
                    doctor_id=created_users[0].id if created_users else None,
                    **patient_data
                )
                db.session.add(patient)
                created_patients.append(patient)
        
        db.session.commit()
        click.echo(f'Created {len(created_patients)} patients.')
        
        # Create sample records
        if created_patients:
            records_data = [
                {
                    'record_type': 'consultation',
                    'title': 'Annual Checkup',
                    'description': 'Routine annual physical examination',
                    'content': 'Patient presents for annual checkup. Vital signs normal. No complaints. Physical examination unremarkable.',
                    'priority': 'normal'
                },
                {
                    'record_type': 'lab_result',
                    'title': 'Blood Test Results',
                    'description': 'Complete blood count and metabolic panel',
                    'content': 'CBC: WBC 7.2, RBC 4.8, Hgb 14.2, Hct 42.1. Metabolic panel: Glucose 95, BUN 15, Creatinine 0.9.',
                    'priority': 'normal'
                },
                {
                    'record_type': 'prescription',
                    'title': 'Medication Prescription',
                    'description': 'Prescription for chronic condition management',
                    'content': 'Prescribed: Metformin 500mg twice daily for diabetes management. Follow up in 3 months.',
                    'priority': 'normal'
                }
            ]
            
            created_records = []
            for record_data in records_data:
                record = Record(
                    record_id=Record.generate_record_id(),
                    patient_id=created_patients[0].id,
                    created_by_id=created_users[0].id if created_users else None,
                    **record_data
                )
                db.session.add(record)
                created_records.append(record)
            
            db.session.commit()
            click.echo(f'Created {len(created_records)} records.')
        
        click.echo('Database seeding completed successfully.')
        logger.info("Database seeded with sample data")
        
    except Exception as e:
        click.echo(f'Error seeding database: {e}')
        logger.error("Database seeding failed", error=str(e))
        db.session.rollback()

@click.command('generate-key')
@with_appcontext
def generate_key():
    """Generate a new encryption key."""
    try:
        key = generate_encryption_key()
        click.echo(f'Generated encryption key: {key}')
        click.echo('Add this key to your environment variables as ENCRYPTION_KEY')
        logger.info("Encryption key generated")
    except Exception as e:
        click.echo(f'Error generating encryption key: {e}')
        logger.error("Encryption key generation failed", error=str(e))

@click.command('reset-db')
@with_appcontext
def reset_db():
    """Reset the database (drop all tables and recreate)."""
    if click.confirm('This will delete all data. Are you sure?'):
        try:
            db.drop_all()
            db.create_all()
            click.echo('Database reset successfully.')
            logger.info("Database reset")
        except Exception as e:
            click.echo(f'Error resetting database: {e}')
            logger.error("Database reset failed", error=str(e))
