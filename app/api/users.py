from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models import User
from app.utils.errors import ValidationError, AuthorizationError, NotFoundError
from app.utils.audit import audit_log, log_data_access, log_data_modification
from app.utils.errors import validate_required_fields, validate_email
import structlog

logger = structlog.get_logger()
users_bp = Blueprint('users', __name__)

def require_admin():
    """Decorator to require admin role"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            
            if not user:
                raise AuthorizationError("User not found")
            
            if not user.has_role('admin'):
                raise AuthorizationError("Admin access required")
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

@users_bp.route('/', methods=['GET'])
@jwt_required()
@require_admin()
def get_users():
    """Get list of users (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        role = request.args.get('role')
        is_active = request.args.get('is_active', type=bool)
        
        # Build query
        query = User.query
        
        # Apply filters
        if role:
            query = query.filter_by(role=role)
        
        if is_active is not None:
            query = query.filter_by(is_active=is_active)
        
        # Order by creation date
        query = query.order_by(User.created_at.desc())
        
        # Paginate results
        pagination = query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        users = []
        for user in pagination.items:
            users.append(user.to_dict())
        
        # Log data access
        log_data_access(current_user_id, 'user', 'list')
        
        return jsonify({
            'users': users,
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
        logger.error("Error retrieving users", error=str(e))
        raise

@users_bp.route('/<int:user_id>', methods=['GET'])
@jwt_required()
@require_admin()
def get_user(user_id):
    """Get specific user details (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        
        user = User.query.get_or_404(user_id)
        user_data = user.to_dict()
        
        # Log data access
        log_data_access(current_user_id, 'user', str(user_id))
        
        return jsonify({
            'user': user_data
        }), 200
        
    except Exception as e:
        logger.error("Error retrieving user", error=str(e))
        raise

@users_bp.route('/', methods=['POST'])
@jwt_required()
@require_admin()
def create_user():
    """Create a new user (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            raise ValidationError("Request body is required")
        
        # Validate required fields
        required_fields = ['username', 'email', 'password', 'first_name', 'last_name', 'role']
        validate_required_fields(data, required_fields)
        
        # Validate email
        validate_email(data['email'])
        
        # Check if username already exists
        if User.get_by_username(data['username']):
            raise ValidationError("Username already exists")
        
        # Check if email already exists
        if User.get_by_email(data['email']):
            raise ValidationError("Email already exists")
        
        # Validate role
        valid_roles = ['admin', 'doctor', 'nurse', 'patient']
        if data['role'] not in valid_roles:
            raise ValidationError(f"Invalid role. Must be one of: {', '.join(valid_roles)}")
        
        # Create user
        user = User(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            first_name=data['first_name'],
            last_name=data['last_name'],
            role=data['role'],
            is_active=data.get('is_active', True),
            is_verified=data.get('is_verified', False)
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Log data creation
        log_data_modification(
            current_user_id, 'user', str(user.id),
            old_values={}, new_values=user.to_dict()
        )
        
        logger.info("User created", user_id=user.id, created_by=current_user_id)
        
        return jsonify({
            'message': 'User created successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        logger.error("Error creating user", error=str(e))
        db.session.rollback()
        raise

@users_bp.route('/<int:user_id>', methods=['PUT'])
@jwt_required()
@require_admin()
def update_user(user_id):
    """Update user information (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        
        user = User.query.get_or_404(user_id)
        
        data = request.get_json()
        if not data:
            raise ValidationError("Request body is required")
        
        # Store old values for audit
        old_values = user.to_dict()
        
        # Update fields
        allowed_fields = ['first_name', 'last_name', 'email', 'role', 'is_active', 'is_verified']
        
        for field in allowed_fields:
            if field in data:
                if field == 'email':
                    validate_email(data[field])
                    # Check if email already exists for other users
                    existing_user = User.get_by_email(data[field])
                    if existing_user and existing_user.id != user_id:
                        raise ValidationError("Email already exists")
                elif field == 'role':
                    valid_roles = ['admin', 'doctor', 'nurse', 'patient']
                    if data[field] not in valid_roles:
                        raise ValidationError(f"Invalid role. Must be one of: {', '.join(valid_roles)}")
                
                setattr(user, field, data[field])
        
        db.session.commit()
        
        # Log data modification
        log_data_modification(
            current_user_id, 'user', str(user_id),
            old_values=old_values, new_values=user.to_dict()
        )
        
        logger.info("User updated", user_id=user_id, updated_by=current_user_id)
        
        return jsonify({
            'message': 'User updated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        logger.error("Error updating user", error=str(e))
        db.session.rollback()
        raise

@users_bp.route('/<int:user_id>/password', methods=['PUT'])
@jwt_required()
@require_admin()
def reset_user_password(user_id):
    """Reset user password (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        
        user = User.query.get_or_404(user_id)
        
        data = request.get_json()
        if not data:
            raise ValidationError("Request body is required")
        
        new_password = data.get('new_password')
        if not new_password:
            raise ValidationError("New password is required")
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        # Log password reset
        audit_log(
            user_id=current_user_id,
            action='password_reset',
            resource_type='user',
            resource_id=str(user_id),
            method='PUT',
            endpoint=f'/api/users/{user_id}/password',
            status_code=200
        )
        
        logger.info("User password reset", user_id=user_id, reset_by=current_user_id)
        
        return jsonify({
            'message': 'Password reset successfully'
        }), 200
        
    except Exception as e:
        logger.error("Error resetting password", error=str(e))
        db.session.rollback()
        raise

@users_bp.route('/<int:user_id>', methods=['DELETE'])
@jwt_required()
@require_admin()
def delete_user(user_id):
    """Delete user (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        
        user = User.query.get_or_404(user_id)
        
        # Prevent self-deletion
        if user.id == current_user_id:
            raise ValidationError("Cannot delete your own account")
        
        # Store user data for audit
        user_data = user.to_dict()
        
        # Delete user
        db.session.delete(user)
        db.session.commit()
        
        # Log deletion
        audit_log(
            user_id=current_user_id,
            action='delete',
            resource_type='user',
            resource_id=str(user_id),
            method='DELETE',
            endpoint=f'/api/users/{user_id}',
            status_code=200,
            old_values=user_data
        )
        
        logger.info("User deleted", user_id=user_id, deleted_by=current_user_id)
        
        return jsonify({
            'message': 'User deleted successfully'
        }), 200
        
    except Exception as e:
        logger.error("Error deleting user", error=str(e))
        db.session.rollback()
        raise

@users_bp.route('/roles', methods=['GET'])
@jwt_required()
def get_roles():
    """Get available user roles"""
    try:
        roles = [
            {'id': 'admin', 'name': 'Administrator', 'description': 'Full system access'},
            {'id': 'doctor', 'name': 'Doctor', 'description': 'Medical staff access'},
            {'id': 'nurse', 'name': 'Nurse', 'description': 'Nursing staff access'},
            {'id': 'patient', 'name': 'Patient', 'description': 'Patient access'}
        ]
        
        return jsonify({
            'roles': roles
        }), 200
        
    except Exception as e:
        logger.error("Error retrieving roles", error=str(e))
        raise

@users_bp.route('/<int:user_id>/activity', methods=['GET'])
@jwt_required()
@require_admin()
def get_user_activity(user_id):
    """Get user activity summary (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        
        user = User.query.get_or_404(user_id)
        
        # Get activity summary
        from app.utils.audit import get_user_activity_summary
        days = request.args.get('days', 30, type=int)
        activity_summary = get_user_activity_summary(user_id, days)
        
        # Log activity access
        log_data_access(current_user_id, 'user_activity', str(user_id))
        
        return jsonify({
            'user_id': user_id,
            'activity_summary': activity_summary
        }), 200
        
    except Exception as e:
        logger.error("Error retrieving user activity", error=str(e))
        raise
