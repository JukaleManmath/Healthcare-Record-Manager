from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models import Patient, User
from app.utils.errors import ValidationError, AuthorizationError, NotFoundError
from app.utils.audit import audit_log, log_data_access, log_data_modification
from app.utils.errors import validate_required_fields, validate_email, validate_phone, validate_ssn
import structlog

logger = structlog.get_logger()
patients_bp = Blueprint('patients', __name__)

def require_role(required_role):
    """Decorator to require specific role"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            
            if not user:
                raise AuthorizationError("User not found")
            
            if not user.has_role(required_role) and not user.has_role('admin'):
                raise AuthorizationError(f"Requires {required_role} role")
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

@patients_bp.route('/', methods=['GET'])
@jwt_required()
@require_role('doctor')
def get_patients():
    """Get list of patients with role-based access"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        search = request.args.get('search', '')
        include_sensitive = user.has_role('admin') or user.has_role('doctor')
        
        # Build query
        query = Patient.query.filter_by(is_active=True)
        
        # Apply search filter
        if search:
            query = query.filter(
                db.or_(
                    Patient.first_name.ilike(f'%{search}%'),
                    Patient.last_name.ilike(f'%{search}%'),
                    Patient.patient_id.ilike(f'%{search}%')
                )
            )
        
        # Apply role-based filtering
        if user.has_role('doctor'):
            query = query.filter_by(doctor_id=current_user_id)
        
        # Paginate results
        pagination = query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        patients = []
        for patient in pagination.items:
            patient_data = patient.to_dict(include_sensitive=include_sensitive)
            patients.append(patient_data)
        
        # Log data access
        log_data_access(current_user_id, 'patient', 'list')
        
        return jsonify({
            'patients': patients,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        }), 200
        
    except Exception as e:
        logger.error("Error retrieving patients", error=str(e))
        raise

@patients_bp.route('/<int:patient_id>', methods=['GET'])
@jwt_required()
@require_role('doctor')
def get_patient(patient_id):
    """Get specific patient details"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        patient = Patient.query.get_or_404(patient_id)
        
        # Check access permissions
        if not user.has_role('admin') and patient.doctor_id != current_user_id:
            raise AuthorizationError("Access denied to this patient")
        
        include_sensitive = user.has_role('admin') or user.has_role('doctor')
        patient_data = patient.to_dict(include_sensitive=include_sensitive)
        
        # Log data access
        log_data_access(current_user_id, 'patient', str(patient_id))
        
        return jsonify({
            'patient': patient_data
        }), 200
        
    except Exception as e:
        logger.error("Error retrieving patient", error=str(e))
        raise

@patients_bp.route('/', methods=['POST'])
@jwt_required()
@require_role('doctor')
def create_patient():
    """Create a new patient"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            raise ValidationError("Request body is required")
        
        # Validate required fields
        required_fields = ['first_name', 'last_name', 'date_of_birth', 'gender']
        validate_required_fields(data, required_fields)
        
        # Validate optional fields
        if 'email' in data and data['email']:
            validate_email(data['email'])
        
        if 'phone' in data and data['phone']:
            validate_phone(data['phone'])
        
        if 'ssn' in data and data['ssn']:
            validate_ssn(data['ssn'])
        
        # Generate patient ID
        patient_id = Patient.generate_patient_id()
        
        # Create patient
        patient = Patient(
            patient_id=patient_id,
            first_name=data['first_name'],
            last_name=data['last_name'],
            date_of_birth=data['date_of_birth'],
            gender=data['gender'],
            doctor_id=current_user_id,
            phone=data.get('phone'),
            email=data.get('email'),
            address=data.get('address'),
            ssn=data.get('ssn'),
            blood_type=data.get('blood_type'),
            allergies=data.get('allergies'),
            emergency_contact=data.get('emergency_contact'),
            insurance_info=data.get('insurance_info')
        )
        
        db.session.add(patient)
        db.session.commit()
        
        # Log data creation
        log_data_modification(
            current_user_id, 'patient', str(patient.id),
            old_values={}, new_values=patient.to_dict(include_sensitive=True)
        )
        
        logger.info("Patient created", patient_id=patient.id, created_by=current_user_id)
        
        return jsonify({
            'message': 'Patient created successfully',
            'patient': patient.to_dict(include_sensitive=True)
        }), 201
        
    except Exception as e:
        logger.error("Error creating patient", error=str(e))
        db.session.rollback()
        raise

@patients_bp.route('/<int:patient_id>', methods=['PUT'])
@jwt_required()
@require_role('doctor')
def update_patient(patient_id):
    """Update patient information"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        patient = Patient.query.get_or_404(patient_id)
        
        # Check access permissions
        if not user.has_role('admin') and patient.doctor_id != current_user_id:
            raise AuthorizationError("Access denied to this patient")
        
        data = request.get_json()
        if not data:
            raise ValidationError("Request body is required")
        
        # Store old values for audit
        old_values = patient.to_dict(include_sensitive=True)
        
        # Update fields
        allowed_fields = [
            'first_name', 'last_name', 'date_of_birth', 'gender',
            'phone', 'email', 'address', 'blood_type', 'allergies',
            'emergency_contact', 'insurance_info'
        ]
        
        for field in allowed_fields:
            if field in data:
                if field == 'phone':
                    if data[field]:
                        validate_phone(data[field])
                    patient.set_phone(data[field])
                elif field == 'email':
                    if data[field]:
                        validate_email(data[field])
                    patient.set_email(data[field])
                elif field == 'address':
                    patient.set_address(data[field])
                else:
                    setattr(patient, field, data[field])
        
        db.session.commit()
        
        # Log data modification
        log_data_modification(
            current_user_id, 'patient', str(patient_id),
            old_values=old_values, new_values=patient.to_dict(include_sensitive=True)
        )
        
        logger.info("Patient updated", patient_id=patient_id, updated_by=current_user_id)
        
        return jsonify({
            'message': 'Patient updated successfully',
            'patient': patient.to_dict(include_sensitive=True)
        }), 200
        
    except Exception as e:
        logger.error("Error updating patient", error=str(e))
        db.session.rollback()
        raise

@patients_bp.route('/<int:patient_id>', methods=['DELETE'])
@jwt_required()
@require_role('admin')
def delete_patient(patient_id):
    """Delete patient (soft delete)"""
    try:
        current_user_id = get_jwt_identity()
        
        patient = Patient.query.get_or_404(patient_id)
        
        # Soft delete
        patient.is_active = False
        db.session.commit()
        
        # Log deletion
        audit_log(
            user_id=current_user_id,
            action='delete',
            resource_type='patient',
            resource_id=str(patient_id),
            method='DELETE',
            endpoint=f'/api/patients/{patient_id}',
            status_code=200,
            old_values=patient.to_dict(include_sensitive=True)
        )
        
        logger.info("Patient deleted", patient_id=patient_id, deleted_by=current_user_id)
        
        return jsonify({
            'message': 'Patient deleted successfully'
        }), 200
        
    except Exception as e:
        logger.error("Error deleting patient", error=str(e))
        db.session.rollback()
        raise

@patients_bp.route('/<int:patient_id>/records', methods=['GET'])
@jwt_required()
@require_role('doctor')
def get_patient_records(patient_id):
    """Get patient medical records"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        patient = Patient.query.get_or_404(patient_id)
        
        # Check access permissions
        if not user.has_role('admin') and patient.doctor_id != current_user_id:
            raise AuthorizationError("Access denied to this patient")
        
        # Get query parameters
        record_type = request.args.get('record_type')
        status = request.args.get('status')
        
        # Get records
        records = Record.get_patient_records(patient_id, record_type, status)
        
        records_data = []
        for record in records:
            record_data = record.to_dict(include_content=True)
            records_data.append(record_data)
        
        # Log data access
        log_data_access(current_user_id, 'patient_records', str(patient_id))
        
        return jsonify({
            'patient_id': patient_id,
            'records': records_data
        }), 200
        
    except Exception as e:
        logger.error("Error retrieving patient records", error=str(e))
        raise

@patients_bp.route('/search', methods=['GET'])
@jwt_required()
@require_role('doctor')
def search_patients():
    """Search patients with advanced filters"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        # Get search parameters
        query = request.args.get('q', '')
        age_min = request.args.get('age_min', type=int)
        age_max = request.args.get('age_max', type=int)
        gender = request.args.get('gender')
        blood_type = request.args.get('blood_type')
        
        # Build query
        patients_query = Patient.query.filter_by(is_active=True)
        
        # Apply role-based filtering
        if user.has_role('doctor'):
            patients_query = patients_query.filter_by(doctor_id=current_user_id)
        
        # Apply search filters
        if query:
            patients_query = patients_query.filter(
                db.or_(
                    Patient.first_name.ilike(f'%{query}%'),
                    Patient.last_name.ilike(f'%{query}%'),
                    Patient.patient_id.ilike(f'%{query}%')
                )
            )
        
        if gender:
            patients_query = patients_query.filter_by(gender=gender)
        
        if blood_type:
            patients_query = patients_query.filter_by(blood_type=blood_type)
        
        # Apply age filters (if implemented)
        # This would require additional date calculations
        
        patients = patients_query.all()
        
        include_sensitive = user.has_role('admin') or user.has_role('doctor')
        patients_data = []
        for patient in patients:
            patient_data = patient.to_dict(include_sensitive=include_sensitive)
            patients_data.append(patient_data)
        
        # Log search
        audit_log(
            user_id=current_user_id,
            action='patient_search',
            resource_type='patient',
            method='GET',
            endpoint='/api/patients/search',
            status_code=200,
            new_values={'search_query': query, 'results_count': len(patients_data)}
        )
        
        return jsonify({
            'patients': patients_data,
            'total': len(patients_data)
        }), 200
        
    except Exception as e:
        logger.error("Error searching patients", error=str(e))
        raise
