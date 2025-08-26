import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from celery import Celery
import structlog

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
cors = CORS()
limiter = Limiter(key_func=get_remote_address)
bcrypt = Bcrypt()
celery = Celery(__name__)

def create_app(config_name=None):
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Load configuration
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')
    
    app.config.from_object(f'config.{config_name.capitalize()}Config')
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    cors.init_app(app)
    limiter.init_app(app)
    bcrypt.init_app(app)
    
    # Configure Celery
    celery.conf.update(app.config)
    
    # Setup logging
    setup_logging(app)
    
    # Register blueprints
    from app.api.auth import auth_bp
    from app.api.patients import patients_bp
    from app.api.records import records_bp
    from app.api.users import users_bp
    from app.api.audit import audit_bp
    from app.api.health import health_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(patients_bp, url_prefix='/api/patients')
    app.register_blueprint(records_bp, url_prefix='/api/records')
    app.register_blueprint(users_bp, url_prefix='/api/users')
    app.register_blueprint(audit_bp, url_prefix='/api/audit')
    app.register_blueprint(health_bp, url_prefix='/api/health')
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register CLI commands
    register_commands(app)
    
    return app

def setup_logging(app):
    """Setup structured logging"""
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

def register_error_handlers(app):
    """Register error handlers"""
    from app.utils.errors import handle_validation_error, handle_auth_error
    
    app.register_error_handler(400, handle_validation_error)
    app.register_error_handler(401, handle_auth_error)
    app.register_error_handler(403, handle_auth_error)
    app.register_error_handler(404, lambda e: {'error': 'Not found'}, 404)
    app.register_error_handler(500, lambda e: {'error': 'Internal server error'}, 500)

def register_commands(app):
    """Register CLI commands"""
    from app.commands import init_db, create_admin, seed_data
    
    app.cli.add_command(init_db)
    app.cli.add_command(create_admin)
    app.cli.add_command(seed_data)

# Import models to ensure they are registered with SQLAlchemy
from app.models import User, Patient, Record, AuditLog, Appointment
