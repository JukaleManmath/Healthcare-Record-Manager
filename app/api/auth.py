from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from app import db, bcrypt
from app.models import User
from app.utils.errors import ValidationError, AuthenticationError, AuthorizationError
from app.utils.audit import audit_log
import structlog

logger = structlog.get_logger()
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        if not data:
            raise ValidationError("Request body is required")
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            raise ValidationError("Username and password are required")
        
        # Find user by username or email
        user = User.get_by_username(username)
        if not user:
            user = User.get_by_email(username)
        
        if not user or not user.check_password(password):
            raise AuthenticationError("Invalid username or password")
        
        if not user.is_active:
            raise AuthenticationError("Account is deactivated")
        
        # Update last login
        user.update_last_login()
        
        # Create tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        # Log successful login
        audit_log(
            user_id=user.id,
            action='login',
            resource_type='user',
            resource_id=str(user.id),
            method='POST',
            endpoint='/api/auth/login',
            status_code=200
        )
        
        logger.info("User logged in successfully", user_id=user.id, username=user.username)
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': user.to_dict()
        }), 200
        
    except (ValidationError, AuthenticationError) as e:
        # Log failed login attempt
        audit_log(
            action='login_failed',
            resource_type='user',
            method='POST',
            endpoint='/api/auth/login',
            status_code=401,
            new_values={'username': username}
        )
        raise e
    except Exception as e:
        logger.error("Login error", error=str(e))
        raise AuthenticationError("Login failed")

@auth_bp.route('/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        if not data:
            raise ValidationError("Request body is required")
        
        # Validate required fields
        required_fields = ['username', 'email', 'password', 'first_name', 'last_name']
        for field in required_fields:
            if not data.get(field):
                raise ValidationError(f"{field} is required")
        
        # Check if username already exists
        if User.get_by_username(data['username']):
            raise ValidationError("Username already exists")
        
        # Check if email already exists
        if User.get_by_email(data['email']):
            raise ValidationError("Email already exists")
        
        # Create new user
        user = User(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            first_name=data['first_name'],
            last_name=data['last_name'],
            role=data.get('role', 'patient')  # Default to patient role
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Log registration
        audit_log(
            user_id=user.id,
            action='register',
            resource_type='user',
            resource_id=str(user.id),
            method='POST',
            endpoint='/api/auth/register',
            status_code=201,
            new_values={'username': user.username, 'email': user.email, 'role': user.role}
        )
        
        logger.info("User registered successfully", user_id=user.id, username=user.username)
        
        return jsonify({
            'message': 'Registration successful',
            'user': user.to_dict()
        }), 201
        
    except ValidationError as e:
        raise e
    except Exception as e:
        logger.error("Registration error", error=str(e))
        db.session.rollback()
        raise ValidationError("Registration failed")

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user or not user.is_active:
            raise AuthenticationError("Invalid token")
        
        access_token = create_access_token(identity=current_user_id)
        
        audit_log(
            user_id=current_user_id,
            action='token_refresh',
            resource_type='user',
            resource_id=str(current_user_id),
            method='POST',
            endpoint='/api/auth/refresh',
            status_code=200
        )
        
        return jsonify({
            'access_token': access_token
        }), 200
        
    except Exception as e:
        logger.error("Token refresh error", error=str(e))
        raise AuthenticationError("Token refresh failed")

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout endpoint"""
    try:
        current_user_id = get_jwt_identity()
        
        audit_log(
            user_id=current_user_id,
            action='logout',
            resource_type='user',
            resource_id=str(current_user_id),
            method='POST',
            endpoint='/api/auth/logout',
            status_code=200
        )
        
        logger.info("User logged out", user_id=current_user_id)
        
        return jsonify({
            'message': 'Logout successful'
        }), 200
        
    except Exception as e:
        logger.error("Logout error", error=str(e))
        raise AuthenticationError("Logout failed")

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    """Get current user profile"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            raise AuthenticationError("User not found")
        
        audit_log(
            user_id=current_user_id,
            action='profile_view',
            resource_type='user',
            resource_id=str(current_user_id),
            method='GET',
            endpoint='/api/auth/profile',
            status_code=200
        )
        
        return jsonify({
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        logger.error("Profile retrieval error", error=str(e))
        raise AuthenticationError("Failed to retrieve profile")

@auth_bp.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """Update current user profile"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            raise AuthenticationError("User not found")
        
        data = request.get_json()
        if not data:
            raise ValidationError("Request body is required")
        
        # Store old values for audit
        old_values = user.to_dict()
        
        # Update allowed fields
        allowed_fields = ['first_name', 'last_name', 'email']
        for field in allowed_fields:
            if field in data:
                setattr(user, field, data[field])
        
        db.session.commit()
        
        audit_log(
            user_id=current_user_id,
            action='profile_update',
            resource_type='user',
            resource_id=str(current_user_id),
            method='PUT',
            endpoint='/api/auth/profile',
            status_code=200,
            old_values=old_values,
            new_values=user.to_dict()
        )
        
        logger.info("Profile updated", user_id=current_user_id)
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': user.to_dict()
        }), 200
        
    except (ValidationError, AuthenticationError) as e:
        raise e
    except Exception as e:
        logger.error("Profile update error", error=str(e))
        db.session.rollback()
        raise ValidationError("Profile update failed")

@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Change user password"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            raise AuthenticationError("User not found")
        
        data = request.get_json()
        if not data:
            raise ValidationError("Request body is required")
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            raise ValidationError("Current password and new password are required")
        
        if not user.check_password(current_password):
            raise ValidationError("Current password is incorrect")
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        audit_log(
            user_id=current_user_id,
            action='password_change',
            resource_type='user',
            resource_id=str(current_user_id),
            method='POST',
            endpoint='/api/auth/change-password',
            status_code=200
        )
        
        logger.info("Password changed", user_id=current_user_id)
        
        return jsonify({
            'message': 'Password changed successfully'
        }), 200
        
    except (ValidationError, AuthenticationError) as e:
        raise e
    except Exception as e:
        logger.error("Password change error", error=str(e))
        db.session.rollback()
        raise ValidationError("Password change failed")
