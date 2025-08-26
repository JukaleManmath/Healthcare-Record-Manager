from flask import jsonify, request
from werkzeug.exceptions import HTTPException
import structlog

logger = structlog.get_logger()

class HealthcareError(Exception):
    """Base exception for healthcare platform"""
    def __init__(self, message, status_code=400, payload=None):
        super().__init__()
        self.message = message
        self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['error'] = self.message
        rv['status_code'] = self.status_code
        return rv

class ValidationError(HealthcareError):
    """Validation error exception"""
    def __init__(self, message, field=None):
        super().__init__(message, status_code=400)
        self.field = field

class AuthenticationError(HealthcareError):
    """Authentication error exception"""
    def __init__(self, message="Authentication required"):
        super().__init__(message, status_code=401)

class AuthorizationError(HealthcareError):
    """Authorization error exception"""
    def __init__(self, message="Insufficient permissions"):
        super().__init__(message, status_code=403)

class NotFoundError(HealthcareError):
    """Resource not found exception"""
    def __init__(self, message="Resource not found"):
        super().__init__(message, status_code=404)

class ConflictError(HealthcareError):
    """Resource conflict exception"""
    def __init__(self, message="Resource conflict"):
        super().__init__(message, status_code=409)

def handle_validation_error(error):
    """Handle validation errors"""
    logger.warning("Validation error", error=str(error), endpoint=request.endpoint)
    return jsonify({
        'error': 'Validation error',
        'message': str(error),
        'status_code': 400
    }), 400

def handle_auth_error(error):
    """Handle authentication/authorization errors"""
    logger.warning("Authentication error", error=str(error), endpoint=request.endpoint)
    return jsonify({
        'error': 'Authentication error',
        'message': str(error),
        'status_code': 401
    }), 401

def handle_healthcare_error(error):
    """Handle custom healthcare errors"""
    logger.error("Healthcare error", error=error.message, status_code=error.status_code)
    return jsonify(error.to_dict()), error.status_code

def handle_generic_error(error):
    """Handle generic errors"""
    if isinstance(error, HealthcareError):
        return handle_healthcare_error(error)
    
    if isinstance(error, HTTPException):
        logger.error("HTTP error", error=error.description, status_code=error.code)
        return jsonify({
            'error': error.name,
            'message': error.description,
            'status_code': error.code
        }), error.code
    
    # Log unexpected errors
    logger.error("Unexpected error", error=str(error), exc_info=True)
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred',
        'status_code': 500
    }), 500

def validate_required_fields(data, required_fields):
    """Validate that required fields are present"""
    missing_fields = []
    for field in required_fields:
        if field not in data or data[field] is None or data[field] == '':
            missing_fields.append(field)
    
    if missing_fields:
        raise ValidationError(f"Missing required fields: {', '.join(missing_fields)}")

def validate_email(email):
    """Validate email format"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValidationError("Invalid email format")

def validate_phone(phone):
    """Validate phone number format"""
    import re
    # Remove all non-digit characters
    digits_only = re.sub(r'\D', '', phone)
    if len(digits_only) < 10 or len(digits_only) > 15:
        raise ValidationError("Invalid phone number format")

def validate_ssn(ssn):
    """Validate SSN format"""
    import re
    # Remove all non-digit characters
    digits_only = re.sub(r'\D', '', ssn)
    if len(digits_only) != 9:
        raise ValidationError("SSN must be 9 digits")

def validate_date_format(date_str, format='%Y-%m-%d'):
    """Validate date format"""
    from datetime import datetime
    try:
        datetime.strptime(date_str, format)
    except ValueError:
        raise ValidationError(f"Invalid date format. Expected format: {format}")

def sanitize_input(data):
    """Sanitize input data to prevent injection attacks"""
    if isinstance(data, str):
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '{', '}']
        for char in dangerous_chars:
            data = data.replace(char, '')
        return data.strip()
    elif isinstance(data, dict):
        return {key: sanitize_input(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    else:
        return data
