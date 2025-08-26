from flask import Blueprint, jsonify
from app import db
import structlog
import psutil
import os
from datetime import datetime

logger = structlog.get_logger()
health_bp = Blueprint('health', __name__)

@health_bp.route('/health', methods=['GET'])
def health_check():
    """Basic health check endpoint"""
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        db_status = 'healthy'
    except Exception as e:
        logger.error("Database health check failed", error=str(e))
        db_status = 'unhealthy'
    
    # Get system information
    system_info = {
        'timestamp': datetime.utcnow().isoformat(),
        'status': 'healthy' if db_status == 'healthy' else 'unhealthy',
        'database': db_status,
        'version': '1.0.0',
        'environment': os.getenv('FLASK_ENV', 'development')
    }
    
    status_code = 200 if db_status == 'healthy' else 503
    
    return jsonify(system_info), status_code

@health_bp.route('/health/detailed', methods=['GET'])
def detailed_health_check():
    """Detailed health check with system metrics"""
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        db_status = 'healthy'
    except Exception as e:
        logger.error("Database health check failed", error=str(e))
        db_status = 'unhealthy'
    
    # Get system metrics
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # Get process information
    process = psutil.Process()
    process_memory = process.memory_info()
    
    # Check Redis connection (if available)
    try:
        import redis
        redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
        redis_client.ping()
        redis_status = 'healthy'
    except Exception as e:
        logger.warning("Redis health check failed", error=str(e))
        redis_status = 'unhealthy'
    
    detailed_info = {
        'timestamp': datetime.utcnow().isoformat(),
        'status': 'healthy' if all([db_status == 'healthy', redis_status == 'healthy']) else 'unhealthy',
        'services': {
            'database': db_status,
            'redis': redis_status
        },
        'system': {
            'cpu_percent': cpu_percent,
            'memory': {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent,
                'used': memory.used
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': (disk.used / disk.total) * 100
            }
        },
        'process': {
            'memory_rss': process_memory.rss,
            'memory_vms': process_memory.vms,
            'cpu_percent': process.cpu_percent(),
            'num_threads': process.num_threads(),
            'create_time': datetime.fromtimestamp(process.create_time()).isoformat()
        },
        'version': '1.0.0',
        'environment': os.getenv('FLASK_ENV', 'development')
    }
    
    status_code = 200 if detailed_info['status'] == 'healthy' else 503
    
    return jsonify(detailed_info), status_code

@health_bp.route('/health/ready', methods=['GET'])
def readiness_check():
    """Readiness check for Kubernetes"""
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        db_status = 'ready'
    except Exception as e:
        logger.error("Database readiness check failed", error=str(e))
        db_status = 'not_ready'
    
    # Check Redis connection
    try:
        import redis
        redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))
        redis_client.ping()
        redis_status = 'ready'
    except Exception as e:
        logger.warning("Redis readiness check failed", error=str(e))
        redis_status = 'not_ready'
    
    readiness_info = {
        'status': 'ready' if all([db_status == 'ready', redis_status == 'ready']) else 'not_ready',
        'database': db_status,
        'redis': redis_status,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    status_code = 200 if readiness_info['status'] == 'ready' else 503
    
    return jsonify(readiness_info), status_code

@health_bp.route('/health/live', methods=['GET'])
def liveness_check():
    """Liveness check for Kubernetes"""
    try:
        # Simple check to ensure the application is running
        liveness_info = {
            'status': 'alive',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(liveness_info), 200
        
    except Exception as e:
        logger.error("Liveness check failed", error=str(e))
        return jsonify({
            'status': 'dead',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503

@health_bp.route('/metrics', methods=['GET'])
def metrics():
    """Prometheus metrics endpoint"""
    try:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        
        # Import and register metrics
        from prometheus_client import Counter, Histogram, Gauge
        import time
        
        # Define metrics
        request_count = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
        request_duration = Histogram('http_request_duration_seconds', 'HTTP request duration')
        active_users = Gauge('active_users', 'Number of active users')
        
        # Generate metrics
        metrics_data = generate_latest()
        
        return metrics_data, 200, {'Content-Type': CONTENT_TYPE_LATEST}
        
    except ImportError:
        # Prometheus client not available
        return jsonify({
            'error': 'Prometheus metrics not available',
            'timestamp': datetime.utcnow().isoformat()
        }), 501
    except Exception as e:
        logger.error("Metrics generation failed", error=str(e))
        return jsonify({
            'error': 'Failed to generate metrics',
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@health_bp.route('/info', methods=['GET'])
def system_info():
    """System information endpoint"""
    try:
        import platform
        
        info = {
            'application': {
                'name': 'Healthcare Record Automation Platform',
                'version': '1.0.0',
                'environment': os.getenv('FLASK_ENV', 'development'),
                'startup_time': datetime.utcnow().isoformat()
            },
            'system': {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor()
            },
            'dependencies': {
                'flask': '2.3.3',
                'sqlalchemy': '1.4.41',
                'postgresql': '15',
                'redis': '7'
            },
            'features': [
                'Role-based access control (RBAC)',
                'HIPAA-compliant data encryption',
                'Comprehensive audit logging',
                'Automated record processing',
                'AWS integration',
                'Docker containerization'
            ]
        }
        
        return jsonify(info), 200
        
    except Exception as e:
        logger.error("System info generation failed", error=str(e))
        return jsonify({
            'error': 'Failed to generate system info',
            'timestamp': datetime.utcnow().isoformat()
        }), 500
