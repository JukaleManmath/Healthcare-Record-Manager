from flask import request, g
from app.models import AuditLog
from app import db
import structlog

logger = structlog.get_logger()

def audit_log(user_id=None, session_id=None, ip_address=None, user_agent=None,
              action=None, resource_type=None, resource_id=None, method=None,
              endpoint=None, status_code=None, old_values=None, new_values=None,
              duration_ms=None):
    """Create audit log entry"""
    try:
        # Get user ID from JWT if not provided
        if user_id is None:
            from flask_jwt_extended import get_jwt_identity
            try:
                user_id = get_jwt_identity()
            except:
                pass
        
        # Get request information if not provided
        if ip_address is None:
            ip_address = request.remote_addr if request else None
        
        if user_agent is None:
            user_agent = request.headers.get('User-Agent') if request else None
        
        if method is None:
            method = request.method if request else None
        
        if endpoint is None:
            endpoint = request.endpoint if request else None
        
        # Create audit log entry
        log_entry = AuditLog(
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            old_values=old_values,
            new_values=new_values,
            duration_ms=duration_ms
        )
        
        # Analyze risk level
        log_entry.analyze_risk()
        
        # Add to database
        db.session.add(log_entry)
        db.session.commit()
        
        logger.info("Audit log created", 
                   action=action, 
                   resource_type=resource_type, 
                   resource_id=resource_id,
                   user_id=user_id,
                   risk_level=log_entry.risk_level)
        
        return log_entry
        
    except Exception as e:
        logger.error("Failed to create audit log", error=str(e))
        db.session.rollback()
        # Don't raise the exception to avoid breaking the main functionality

def audit_decorator(action, resource_type=None):
    """Decorator to automatically audit function calls"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            import time
            start_time = time.time()
            
            try:
                # Execute the function
                result = func(*args, **kwargs)
                
                # Calculate duration
                duration_ms = int((time.time() - start_time) * 1000)
                
                # Create audit log
                audit_log(
                    action=action,
                    resource_type=resource_type,
                    method=request.method if request else None,
                    endpoint=request.endpoint if request else None,
                    status_code=200,
                    duration_ms=duration_ms
                )
                
                return result
                
            except Exception as e:
                # Calculate duration
                duration_ms = int((time.time() - start_time) * 1000)
                
                # Create audit log for error
                audit_log(
                    action=f"{action}_error",
                    resource_type=resource_type,
                    method=request.method if request else None,
                    endpoint=request.endpoint if request else None,
                    status_code=500,
                    duration_ms=duration_ms,
                    new_values={'error': str(e)}
                )
                
                raise e
        
        return wrapper
    return decorator

def log_data_access(user_id, resource_type, resource_id, access_type='read'):
    """Log data access for compliance"""
    audit_log(
        user_id=user_id,
        action=f"{access_type}_access",
        resource_type=resource_type,
        resource_id=resource_id,
        method=request.method if request else None,
        endpoint=request.endpoint if request else None,
        status_code=200
    )

def log_data_modification(user_id, resource_type, resource_id, old_values, new_values):
    """Log data modification for compliance"""
    audit_log(
        user_id=user_id,
        action='data_modification',
        resource_type=resource_type,
        resource_id=resource_id,
        method=request.method if request else None,
        endpoint=request.endpoint if request else None,
        status_code=200,
        old_values=old_values,
        new_values=new_values
    )

def log_security_event(user_id, event_type, details=None):
    """Log security-related events"""
    audit_log(
        user_id=user_id,
        action=f"security_{event_type}",
        resource_type='security',
        method=request.method if request else None,
        endpoint=request.endpoint if request else None,
        status_code=200,
        new_values=details
    )

def get_user_activity_summary(user_id, days=30):
    """Get summary of user activity for the specified period"""
    from datetime import datetime, timedelta
    
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Get activity logs
    logs = AuditLog.get_user_activity(user_id, start_date=start_date)
    
    # Analyze activity
    activity_summary = {
        'total_actions': len(logs),
        'login_count': len([log for log in logs if log.action == 'login']),
        'data_access_count': len([log for log in logs if 'access' in log.action]),
        'data_modification_count': len([log for log in logs if log.action == 'data_modification']),
        'suspicious_actions': len([log for log in logs if log.is_suspicious]),
        'high_risk_actions': len([log for log in logs if log.risk_level in ['high', 'critical']]),
        'most_accessed_resources': {},
        'activity_by_day': {}
    }
    
    # Count resource access
    for log in logs:
        if log.resource_type:
            activity_summary['most_accessed_resources'][log.resource_type] = \
                activity_summary['most_accessed_resources'].get(log.resource_type, 0) + 1
        
        # Group by day
        day = log.timestamp.strftime('%Y-%m-%d')
        activity_summary['activity_by_day'][day] = \
            activity_summary['activity_by_day'].get(day, 0) + 1
    
    return activity_summary

def get_system_activity_summary(days=30):
    """Get summary of system activity for the specified period"""
    from datetime import datetime, timedelta
    
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Get all logs
    logs = AuditLog.query.filter(AuditLog.timestamp >= start_date).all()
    
    # Analyze system activity
    system_summary = {
        'total_actions': len(logs),
        'unique_users': len(set(log.user_id for log in logs if log.user_id)),
        'login_attempts': len([log for log in logs if log.action in ['login', 'login_failed']]),
        'failed_logins': len([log for log in logs if log.action == 'login_failed']),
        'suspicious_activities': len([log for log in logs if log.is_suspicious]),
        'high_risk_activities': len([log for log in logs if log.risk_level in ['high', 'critical']]),
        'most_active_users': {},
        'most_accessed_resources': {},
        'activity_by_hour': {}
    }
    
    # Count user activity
    for log in logs:
        if log.user_id:
            system_summary['most_active_users'][log.user_id] = \
                system_summary['most_active_users'].get(log.user_id, 0) + 1
        
        if log.resource_type:
            system_summary['most_accessed_resources'][log.resource_type] = \
                system_summary['most_accessed_resources'].get(log.resource_type, 0) + 1
        
        # Group by hour
        hour = log.timestamp.strftime('%Y-%m-%d %H:00')
        system_summary['activity_by_hour'][hour] = \
            system_summary['activity_by_hour'].get(hour, 0) + 1
    
    return system_summary
