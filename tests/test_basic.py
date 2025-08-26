import pytest
from app import create_app, db
from app.models import User, Patient, Record
from app.utils.encryption import encrypt_data, decrypt_data

@pytest.fixture
def app():
    """Create application for testing"""
    app = create_app('testing')
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()

@pytest.fixture
def runner(app):
    """Create test runner"""
    return app.test_cli_runner()

def test_health_check(client):
    """Test health check endpoint"""
    response = client.get('/api/health/health')
    assert response.status_code == 200
    data = response.get_json()
    assert 'status' in data
    assert data['status'] in ['healthy', 'unhealthy']

def test_encryption():
    """Test encryption and decryption"""
    test_data = "sensitive patient information"
    encrypted = encrypt_data(test_data)
    decrypted = decrypt_data(encrypted)
    assert decrypted == test_data

def test_user_creation(app):
    """Test user creation"""
    with app.app_context():
        user = User(
            username='testuser',
            email='test@example.com',
            password='password123',
            first_name='Test',
            last_name='User',
            role='doctor'
        )
        db.session.add(user)
        db.session.commit()
        
        assert user.id is not None
        assert user.check_password('password123')
        assert user.has_role('doctor')

def test_patient_creation(app):
    """Test patient creation with encrypted data"""
    with app.app_context():
        patient = Patient(
            patient_id='TEST12345',
            first_name='John',
            last_name='Doe',
            date_of_birth='1990-01-01',
            gender='Male',
            phone='+1-555-0123',
            email='john.doe@email.com',
            address='123 Test St'
        )
        db.session.add(patient)
        db.session.commit()
        
        assert patient.id is not None
        assert patient.get_phone() == '+1-555-0123'
        assert patient.get_email() == 'john.doe@email.com'

def test_record_creation(app):
    """Test medical record creation"""
    with app.app_context():
        # Create a user first
        user = User(
            username='doctor',
            email='doctor@example.com',
            password='password123',
            first_name='Dr',
            last_name='Smith',
            role='doctor'
        )
        db.session.add(user)
        
        # Create a patient
        patient = Patient(
            patient_id='PAT12345',
            first_name='Jane',
            last_name='Smith',
            date_of_birth='1985-05-15',
            gender='Female'
        )
        db.session.add(patient)
        db.session.commit()
        
        # Create a record
        record = Record(
            record_id='REC12345',
            patient_id=patient.id,
            created_by_id=user.id,
            record_type='consultation',
            title='Annual Checkup',
            content='Patient presents for annual checkup. All vital signs normal.'
        )
        db.session.add(record)
        db.session.commit()
        
        assert record.id is not None
        assert record.get_content() == 'Patient presents for annual checkup. All vital signs normal.'

def test_authentication(client):
    """Test user authentication"""
    # This would require setting up a test database with a user
    # For now, just test the endpoint structure
    response = client.post('/api/auth/login', json={
        'username': 'nonexistent',
        'password': 'wrong'
    })
    assert response.status_code in [401, 400]  # Should fail

def test_api_structure(client):
    """Test that API endpoints are accessible"""
    endpoints = [
        '/api/health/health',
        '/api/health/info',
        '/api/auth/login',  # POST only
    ]
    
    for endpoint in endpoints:
        if endpoint == '/api/auth/login':
            response = client.post(endpoint, json={})
        else:
            response = client.get(endpoint)
        # Should not return 404 (endpoint exists)
        assert response.status_code != 404
