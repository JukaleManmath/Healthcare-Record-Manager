from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models import AuditLog, User
from app.utils.errors import AuthorizationError
from app.utils.audit import get_system_activity_summary
import structlog

logger = structlog.get_logger()
audit_bp = Blueprint('audit', __name__)

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

@audit_bp.route('/logs', methods=['GET'])
@jwt_required()
@require_admin()
def get_audit_logs():
    """Get audit logs (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 200)
        user_id = request.args.get('user_id', type=int)
        action = request.args.get('action')
        resource_type = request.args.get('resource_type')
        risk_level = request.args.get('risk_level')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Build query
        query = AuditLog.query
        
        # Apply filters
        if user_id:
            query = query.filter_by(user_id=user_id)
        
        if action:
            query = query.filter_by(action=action)
        
        if resource_type:
            query = query.filter_by(resource_type=resource_type)
        
        if risk_level:
            query = query.filter_by(risk_level=risk_level)
        
        if start_date:
            from datetime import datetime
            start_datetime = datetime.fromisoformat(start_date)
            query = query.filter(AuditLog.timestamp >= start_datetime)
        
        if end_date:
            from datetime import datetime
            end_datetime = datetime.fromisoformat(end_date)
            query = query.filter(AuditLog.timestamp <= end_datetime)
        
        # Order by timestamp (newest first)
        query = query.order_by(AuditLog.timestamp.desc())
        
        # Paginate results
        pagination = query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        logs = []
        for log in pagination.items:
            logs.append(log.to_dict())
        
        return jsonify({
            'logs': logs,
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
        logger.error("Error retrieving audit logs", error=str(e))
        raise

@audit_bp.route('/suspicious', methods=['GET'])
@jwt_required()
@require_admin()
def get_suspicious_activity():
    """Get suspicious activity logs (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 200)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Build query for suspicious activities
        query = AuditLog.query.filter_by(is_suspicious=True)
        
        # Apply date filters
        if start_date:
            from datetime import datetime
            start_datetime = datetime.fromisoformat(start_date)
            query = query.filter(AuditLog.timestamp >= start_datetime)
        
        if end_date:
            from datetime import datetime
            end_datetime = datetime.fromisoformat(end_date)
            query = query.filter(AuditLog.timestamp <= end_datetime)
        
        # Order by timestamp (newest first)
        query = query.order_by(AuditLog.timestamp.desc())
        
        # Paginate results
        pagination = query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        logs = []
        for log in pagination.items:
            logs.append(log.to_dict())
        
        return jsonify({
            'suspicious_activities': logs,
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
        logger.error("Error retrieving suspicious activity", error=str(e))
        raise

@audit_bp.route('/summary', methods=['GET'])
@jwt_required()
@require_admin()
def get_audit_summary():
    """Get audit summary statistics (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        
        # Get days parameter
        days = request.args.get('days', 30, type=int)
        
        # Get system activity summary
        system_summary = get_system_activity_summary(days)
        
        return jsonify({
            'summary': system_summary,
            'period_days': days
        }), 200
        
    except Exception as e:
        logger.error("Error retrieving audit summary", error=str(e))
        raise

@audit_bp.route('/user/<int:user_id>', methods=['GET'])
@jwt_required()
@require_admin()
def get_user_audit_logs(user_id):
    """Get audit logs for specific user (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        
        # Check if user exists
        user = User.query.get_or_404(user_id)
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 200)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Get user activity logs
        logs = AuditLog.get_user_activity(user_id, start_date, end_date)
        
        # Paginate results manually
        total = len(logs)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_logs = logs[start_idx:end_idx]
        
        logs_data = []
        for log in paginated_logs:
            logs_data.append(log.to_dict())
        
        return jsonify({
            'user_id': user_id,
            'logs': logs_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page,
                'has_next': end_idx < total,
                'has_prev': page > 1
            }
        }), 200
        
    except Exception as e:
        logger.error("Error retrieving user audit logs", error=str(e))
        raise

@audit_bp.route('/resource/<resource_type>/<resource_id>', methods=['GET'])
@jwt_required()
@require_admin()
def get_resource_audit_logs(resource_type, resource_id):
    """Get audit logs for specific resource (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 200)
        
        # Get resource history
        logs = AuditLog.get_resource_history(resource_type, resource_id)
        
        # Paginate results manually
        total = len(logs)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_logs = logs[start_idx:end_idx]
        
        logs_data = []
        for log in paginated_logs:
            logs_data.append(log.to_dict())
        
        return jsonify({
            'resource_type': resource_type,
            'resource_id': resource_id,
            'logs': logs_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page,
                'has_next': end_idx < total,
                'has_prev': page > 1
            }
        }), 200
        
    except Exception as e:
        logger.error("Error retrieving resource audit logs", error=str(e))
        raise

@audit_bp.route('/export', methods=['GET'])
@jwt_required()
@require_admin()
def export_audit_logs():
    """Export audit logs to CSV (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        
        # Get query parameters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        format_type = request.args.get('format', 'csv')
        
        # Build query
        query = AuditLog.query
        
        # Apply date filters
        if start_date:
            from datetime import datetime
            start_datetime = datetime.fromisoformat(start_date)
            query = query.filter(AuditLog.timestamp >= start_datetime)
        
        if end_date:
            from datetime import datetime
            end_datetime = datetime.fromisoformat(end_date)
            query = query.filter(AuditLog.timestamp <= end_datetime)
        
        # Get logs
        logs = query.order_by(AuditLog.timestamp.desc()).all()
        
        if format_type == 'csv':
            import csv
            import io
            from datetime import datetime
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                'Timestamp', 'User ID', 'Action', 'Resource Type', 'Resource ID',
                'Method', 'Endpoint', 'Status Code', 'Risk Level', 'IP Address'
            ])
            
            # Write data
            for log in logs:
                writer.writerow([
                    log.timestamp.isoformat(),
                    log.user_id,
                    log.action,
                    log.resource_type,
                    log.resource_id,
                    log.method,
                    log.endpoint,
                    log.status_code,
                    log.risk_level,
                    log.ip_address
                ])
            
            output.seek(0)
            
            # Log export
            audit_log(
                user_id=current_user_id,
                action='audit_export',
                resource_type='audit',
                method='GET',
                endpoint='/api/audit/export',
                status_code=200,
                new_values={'export_count': len(logs), 'format': format_type}
            )
            
            return output.getvalue(), 200, {
                'Content-Type': 'text/csv',
                'Content-Disposition': f'attachment; filename=audit_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        
        else:
            # Return JSON format
            logs_data = []
            for log in logs:
                logs_data.append(log.to_dict())
            
            return jsonify({
                'logs': logs_data,
                'total': len(logs_data)
            }), 200
        
    except Exception as e:
        logger.error("Error exporting audit logs", error=str(e))
        raise

@audit_bp.route('/alerts', methods=['GET'])
@jwt_required()
@require_admin()
def get_security_alerts():
    """Get security alerts based on audit logs (admin only)"""
    try:
        current_user_id = get_jwt_identity()
        
        # Get query parameters
        days = request.args.get('days', 7, type=int)
        
        from datetime import datetime, timedelta
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Get high-risk activities
        high_risk_logs = AuditLog.query.filter(
            AuditLog.timestamp >= start_date,
            AuditLog.risk_level.in_(['high', 'critical'])
        ).order_by(AuditLog.timestamp.desc()).all()
        
        # Get failed login attempts
        failed_logins = AuditLog.query.filter(
            AuditLog.timestamp >= start_date,
            AuditLog.action == 'login_failed'
        ).order_by(AuditLog.timestamp.desc()).all()
        
        # Get suspicious activities
        suspicious_activities = AuditLog.query.filter(
            AuditLog.timestamp >= start_date,
            AuditLog.is_suspicious == True
        ).order_by(AuditLog.timestamp.desc()).all()
        
        alerts = {
            'high_risk_activities': [log.to_dict() for log in high_risk_logs],
            'failed_logins': [log.to_dict() for log in failed_logins],
            'suspicious_activities': [log.to_dict() for log in suspicious_activities],
            'summary': {
                'high_risk_count': len(high_risk_logs),
                'failed_logins_count': len(failed_logins),
                'suspicious_count': len(suspicious_activities),
                'total_alerts': len(high_risk_logs) + len(failed_logins) + len(suspicious_activities)
            }
        }
        
        return jsonify(alerts), 200
        
    except Exception as e:
        logger.error("Error retrieving security alerts", error=str(e))
        raise
