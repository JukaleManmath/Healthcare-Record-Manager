from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models import Record, Patient, User
from app.utils.errors import ValidationError, AuthorizationError, NotFoundError
from app.utils.audit import audit_log, log_data_access, log_data_modification
from app.utils.errors import validate_required_fields
import structlog

logger = structlog.get_logger()
records_bp = Blueprint('records', __name__)

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

@records_bp.route('/', methods=['GET'])
@jwt_required()
@require_role('doctor')
def get_records():
    """Get list of medical records with role-based access"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        record_type = request.args.get('record_type')
        status = request.args.get('status')
        patient_id = request.args.get('patient_id', type=int)
        
        # Build query
        query = Record.query
        
        # Apply filters
        if record_type:
            query = query.filter_by(record_type=record_type)
        
        if status:
            query = query.filter_by(status=status)
        
        if patient_id:
            query = query.filter_by(patient_id=patient_id)
        
        # Apply role-based filtering
        if user.has_role('doctor') and not user.has_role('admin'):
            # Doctors can only see records for their patients
            query = query.join(Patient).filter(Patient.doctor_id == current_user_id)
        
        # Order by creation date
        query = query.order_by(Record.created_at.desc())
        
        # Paginate results
        pagination = query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        records = []
        for record in pagination.items:
            record_data = record.to_dict(include_content=False)  # Don't include content in list
            records.append(record_data)
        
        # Log data access
        log_data_access(current_user_id, 'record', 'list')
        
        return jsonify({
            'records': records,
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
        logger.error("Error retrieving records", error=str(e))
        raise

@records_bp.route('/<int:record_id>', methods=['GET'])
@jwt_required()
@require_role('doctor')
def get_record(record_id):
    """Get specific medical record details"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        record = Record.query.get_or_404(record_id)
        
        # Check access permissions
        if user.has_role('doctor') and not user.has_role('admin'):
            patient = Patient.query.get(record.patient_id)
            if not patient or patient.doctor_id != current_user_id:
                raise AuthorizationError("Access denied to this record")
        
        record_data = record.to_dict(include_content=True)
        
        # Log data access
        log_data_access(current_user_id, 'record', str(record_id))
        
        return jsonify({
            'record': record_data
        }), 200
        
    except Exception as e:
        logger.error("Error retrieving record", error=str(e))
        raise

@records_bp.route('/', methods=['POST'])
@jwt_required()
@require_role('doctor')
def create_record():
    """Create a new medical record"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            raise ValidationError("Request body is required")
        
        # Validate required fields
        required_fields = ['patient_id', 'record_type', 'title', 'content']
        validate_required_fields(data, required_fields)
        
        # Check if patient exists and user has access
        patient = Patient.query.get_or_404(data['patient_id'])
        user = User.query.get(current_user_id)
        
        if user.has_role('doctor') and not user.has_role('admin'):
            if patient.doctor_id != current_user_id:
                raise AuthorizationError("Access denied to this patient")
        
        # Generate record ID
        record_id = Record.generate_record_id()
        
        # Create record
        record = Record(
            record_id=record_id,
            patient_id=data['patient_id'],
            created_by_id=current_user_id,
            record_type=data['record_type'],
            title=data['title'],
            description=data.get('description'),
            content=data['content'],
            attachments=data.get('attachments'),
            priority=data.get('priority', 'normal')
        )
        
        db.session.add(record)
        db.session.commit()
        
        # Log data creation
        log_data_modification(
            current_user_id, 'record', str(record.id),
            old_values={}, new_values=record.to_dict(include_content=True)
        )
        
        logger.info("Record created", record_id=record.id, created_by=current_user_id)
        
        return jsonify({
            'message': 'Record created successfully',
            'record': record.to_dict(include_content=True)
        }), 201
        
    except Exception as e:
        logger.error("Error creating record", error=str(e))
        db.session.rollback()
        raise

@records_bp.route('/<int:record_id>', methods=['PUT'])
@jwt_required()
@require_role('doctor')
def update_record(record_id):
    """Update medical record"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        record = Record.query.get_or_404(record_id)
        
        # Check access permissions
        if user.has_role('doctor') and not user.has_role('admin'):
            patient = Patient.query.get(record.patient_id)
            if not patient or patient.doctor_id != current_user_id:
                raise AuthorizationError("Access denied to this record")
        
        data = request.get_json()
        if not data:
            raise ValidationError("Request body is required")
        
        # Store old values for audit
        old_values = record.to_dict(include_content=True)
        
        # Update fields
        allowed_fields = ['title', 'description', 'content', 'attachments', 'priority']
        
        for field in allowed_fields:
            if field in data:
                if field == 'content':
                    record.set_content(data[field])
                elif field == 'attachments':
                    record.set_attachments(data[field])
                else:
                    setattr(record, field, data[field])
        
        db.session.commit()
        
        # Log data modification
        log_data_modification(
            current_user_id, 'record', str(record_id),
            old_values=old_values, new_values=record.to_dict(include_content=True)
        )
        
        logger.info("Record updated", record_id=record_id, updated_by=current_user_id)
        
        return jsonify({
            'message': 'Record updated successfully',
            'record': record.to_dict(include_content=True)
        }), 200
        
    except Exception as e:
        logger.error("Error updating record", error=str(e))
        db.session.rollback()
        raise

@records_bp.route('/<int:record_id>/version', methods=['POST'])
@jwt_required()
@require_role('doctor')
def create_record_version(record_id):
    """Create a new version of a medical record"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        record = Record.query.get_or_404(record_id)
        
        # Check access permissions
        if user.has_role('doctor') and not user.has_role('admin'):
            patient = Patient.query.get(record.patient_id)
            if not patient or patient.doctor_id != current_user_id:
                raise AuthorizationError("Access denied to this record")
        
        data = request.get_json()
        if not data:
            raise ValidationError("Request body is required")
        
        # Create new version
        new_record = record.create_version(
            new_content=data.get('content', record.get_content()),
            new_attachments=data.get('attachments', record.get_attachments())
        )
        
        db.session.add(new_record)
        db.session.commit()
        
        # Log version creation
        audit_log(
            user_id=current_user_id,
            action='record_version_create',
            resource_type='record',
            resource_id=str(record_id),
            method='POST',
            endpoint=f'/api/records/{record_id}/version',
            status_code=201,
            new_values={'new_version_id': new_record.id}
        )
        
        logger.info("Record version created", 
                   original_record_id=record_id, 
                   new_version_id=new_record.id,
                   created_by=current_user_id)
        
        return jsonify({
            'message': 'Record version created successfully',
            'record': new_record.to_dict(include_content=True)
        }), 201
        
    except Exception as e:
        logger.error("Error creating record version", error=str(e))
        db.session.rollback()
        raise

@records_bp.route('/<int:record_id>/approve', methods=['POST'])
@jwt_required()
@require_role('doctor')
def approve_record(record_id):
    """Approve a medical record"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        record = Record.query.get_or_404(record_id)
        
        # Check access permissions
        if user.has_role('doctor') and not user.has_role('admin'):
            patient = Patient.query.get(record.patient_id)
            if not patient or patient.doctor_id != current_user_id:
                raise AuthorizationError("Access denied to this record")
        
        # Approve record
        record.approve(current_user_id)
        db.session.commit()
        
        # Log approval
        audit_log(
            user_id=current_user_id,
            action='record_approve',
            resource_type='record',
            resource_id=str(record_id),
            method='POST',
            endpoint=f'/api/records/{record_id}/approve',
            status_code=200
        )
        
        logger.info("Record approved", record_id=record_id, approved_by=current_user_id)
        
        return jsonify({
            'message': 'Record approved successfully',
            'record': record.to_dict(include_content=True)
        }), 200
        
    except Exception as e:
        logger.error("Error approving record", error=str(e))
        db.session.rollback()
        raise

@records_bp.route('/<int:record_id>/review', methods=['POST'])
@jwt_required()
@require_role('doctor')
def review_record(record_id):
    """Review a medical record"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        record = Record.query.get_or_404(record_id)
        
        # Check access permissions
        if user.has_role('doctor') and not user.has_role('admin'):
            patient = Patient.query.get(record.patient_id)
            if not patient or patient.doctor_id != current_user_id:
                raise AuthorizationError("Access denied to this record")
        
        # Review record
        record.review(current_user_id)
        db.session.commit()
        
        # Log review
        audit_log(
            user_id=current_user_id,
            action='record_review',
            resource_type='record',
            resource_id=str(record_id),
            method='POST',
            endpoint=f'/api/records/{record_id}/review',
            status_code=200
        )
        
        logger.info("Record reviewed", record_id=record_id, reviewed_by=current_user_id)
        
        return jsonify({
            'message': 'Record reviewed successfully',
            'record': record.to_dict(include_content=True)
        }), 200
        
    except Exception as e:
        logger.error("Error reviewing record", error=str(e))
        db.session.rollback()
        raise

@records_bp.route('/<int:record_id>', methods=['DELETE'])
@jwt_required()
@require_role('admin')
def delete_record(record_id):
    """Delete medical record (soft delete)"""
    try:
        current_user_id = get_jwt_identity()
        
        record = Record.query.get_or_404(record_id)
        
        # Soft delete
        record.archive()
        db.session.commit()
        
        # Log deletion
        audit_log(
            user_id=current_user_id,
            action='record_delete',
            resource_type='record',
            resource_id=str(record_id),
            method='DELETE',
            endpoint=f'/api/records/{record_id}',
            status_code=200,
            old_values=record.to_dict(include_content=True)
        )
        
        logger.info("Record deleted", record_id=record_id, deleted_by=current_user_id)
        
        return jsonify({
            'message': 'Record deleted successfully'
        }), 200
        
    except Exception as e:
        logger.error("Error deleting record", error=str(e))
        db.session.rollback()
        raise

@records_bp.route('/types', methods=['GET'])
@jwt_required()
def get_record_types():
    """Get available record types"""
    try:
        record_types = [
            {'id': 'consultation', 'name': 'Consultation'},
            {'id': 'lab_result', 'name': 'Lab Result'},
            {'id': 'prescription', 'name': 'Prescription'},
            {'id': 'imaging', 'name': 'Imaging'},
            {'id': 'surgery', 'name': 'Surgery'},
            {'id': 'emergency', 'name': 'Emergency'},
            {'id': 'follow_up', 'name': 'Follow-up'},
            {'id': 'discharge', 'name': 'Discharge Summary'},
            {'id': 'vaccination', 'name': 'Vaccination'},
            {'id': 'allergy', 'name': 'Allergy Record'}
        ]
        
        return jsonify({
            'record_types': record_types
        }), 200
        
    except Exception as e:
        logger.error("Error retrieving record types", error=str(e))
        raise
