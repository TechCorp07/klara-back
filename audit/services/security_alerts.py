import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from django.db.models import Count, Q, F
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.template.exceptions import TemplateDoesNotExist
from ..models import SecurityAuditLog, PHIAccessLog, AuditEvent
from django.contrib.auth import get_user_model
from django.db.models.functions import Extract

User = get_user_model()
logger = logging.getLogger(__name__)


class SecurityAlertService:
    """Service for security alert management and notifications."""
    
    @staticmethod
    def create_security_alert(event_type, description, severity, user=None, 
                              ip_address=None, user_agent=None, additional_data=None):
        """
        Create a new security alert.
        
        Args:
            event_type: Type of security event (SecurityAuditLog.EventType)
            description: Description of the security event
            severity: Severity level of the event (SecurityAuditLog.Severity)
            user: User involved in the event (if any)
            ip_address: IP address related to the event
            user_agent: User agent related to the event
            additional_data: Additional data related to the event
            
        Returns:
            SecurityAuditLog: The created security alert
        """
        if additional_data is None:
            additional_data = {}
            
        # Validate event type
        if not hasattr(SecurityAuditLog.EventType, event_type):
            valid_types = [e.name for e in SecurityAuditLog.EventType]
            logger.warning(f"Invalid event type: {event_type}. Valid types: {valid_types}")
            # Default to SUSPICIOUS_ACCESS
            event_type = 'SUSPICIOUS_ACCESS'
        
        # Validate severity
        if not hasattr(SecurityAuditLog.Severity, severity):
            valid_severities = [s.name for s in SecurityAuditLog.Severity]
            logger.warning(f"Invalid severity: {severity}. Valid severities: {valid_severities}")
            # Default to MEDIUM
            severity = 'MEDIUM'
            
        alert = SecurityAuditLog.objects.create(
            user=user,
            event_type=event_type,
            description=description,
            severity=severity,
            ip_address=ip_address,
            user_agent=user_agent,
            additional_data=additional_data
        )
        
        # Send notifications for high severity alerts
        if severity in [SecurityAuditLog.Severity.HIGH, SecurityAuditLog.Severity.CRITICAL]:
            SecurityAlertService.send_alert_notification(alert)
            
        return alert
    
    @staticmethod
    def resolve_alert(alert_id, user, notes=''):
        """
        Resolve a security alert.
        
        Args:
            alert_id: ID of the alert to resolve
            user: User resolving the alert
            notes: Resolution notes
            
        Returns:
            SecurityAuditLog: The updated alert or None if not found
        """
        if user is None:
            raise ValueError("User cannot be None when resolving an alert")
            
        try:
            alert = SecurityAuditLog.objects.get(id=alert_id)
            alert.resolve(user, notes)
            
            # Log the resolution as an audit event
            AuditEvent.objects.create(
                user=user,
                event_type=AuditEvent.EventType.UPDATE,
                resource_type='security_alert',
                resource_id=str(alert_id),
                description=f"Resolved security alert: {alert.get_event_type_display()}"
            )
            
            return alert
        except SecurityAuditLog.DoesNotExist:
            logger.error(f"Security alert with ID {alert_id} not found")
            return None
    
    @staticmethod
    def send_alert_notification(alert):
        """
        Send notifications for a security alert.
        
        Args:
            alert: The SecurityAuditLog object
        """
        recipient_emails = getattr(settings, 'SECURITY_ALERT_EMAILS', [])
        if not recipient_emails:
            logger.warning("No security alert email recipients configured")
            return
            
        subject = f"SECURITY ALERT: {alert.get_severity_display()} - {alert.get_event_type_display()}"
        
        context = {
            'alert': alert,
            'app_name': getattr(settings, 'APP_NAME', 'Klararety Health'),
            'dashboard_url': getattr(settings, 'SECURITY_DASHBOARD_URL', ''),
            'timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'severity': alert.get_severity_display(),
            'event_type': alert.get_event_type_display(),
            'user': alert.user.username if alert.user else 'Anonymous',
            'description': alert.description,
            'ip_address': alert.ip_address or 'Unknown'
        }
        
        # Render email content from template
        try:
            html_message = render_to_string('audit/email/security_alert.html', context)
            text_message = render_to_string('audit/email/security_alert.txt', context)
        except TemplateDoesNotExist as e:
            logger.error(f"Template not found for security alert email: {str(e)}")
            # Fallback to plain message
            text_message = f"""
            Security Alert: {alert.get_severity_display()} - {alert.get_event_type_display()}
            
            Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
            User: {alert.user.username if alert.user else 'Anonymous'}
            IP Address: {alert.ip_address or 'Unknown'}
            
            Description: {alert.description}
            
            Please check the security dashboard for more details.
            """
            html_message = f"<html><body>{text_message.replace(chr(10), '<br>')}</body></html>"
        except Exception as e:
            logger.error(f"Error rendering security alert email template: {str(e)}")
            # Fallback to plain message
            text_message = f"""
            Security Alert: {alert.get_severity_display()} - {alert.get_event_type_display()}
            
            Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
            User: {alert.user.username if alert.user else 'Anonymous'}
            IP Address: {alert.ip_address or 'Unknown'}
            
            Description: {alert.description}
            
            Please check the security dashboard for more details.
            """
            html_message = f"<html><body>{text_message.replace(chr(10), '<br>')}</body></html>"
        
        try:
            send_mail(
                subject=subject,
                message=text_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipient_emails,
                html_message=html_message
            )
            logger.info(f"Security alert notification sent: {subject}")
        except Exception as e:
            logger.error(f"Failed to send security alert email: {str(e)}")
    
    @staticmethod
    def detect_suspicious_activity():
        """
        Detect suspicious activity patterns and create alerts.
        
        This method analyzes audit logs and PHI access patterns to detect
        potentially suspicious activities.
        
        Returns:
            list: List of created security alerts
        """
        alerts_created = []
        
        # Detect suspicious activities
        alerts_created.extend(SecurityAlertService._detect_multiple_failed_logins())
        alerts_created.extend(SecurityAlertService._detect_unusual_phi_access())
        alerts_created.extend(SecurityAlertService._detect_after_hours_access())
        alerts_created.extend(SecurityAlertService._detect_unusual_ip_addresses())
        alerts_created.extend(SecurityAlertService._detect_high_volume_access())
        alerts_created.extend(SecurityAlertService._detect_vip_patient_access())
        
        return alerts_created
    
    @staticmethod
    def _detect_multiple_failed_logins():
        """
        Detect multiple failed login attempts.
        
        Looks for patterns of repeated failed authentication attempts that could
        indicate brute force attacks.
        
        Returns:
            list: Security alerts created
        """
        threshold = getattr(settings, 'FAILED_LOGIN_THRESHOLD', 5)
        time_window = getattr(settings, 'FAILED_LOGIN_WINDOW_MINUTES', 15)
        
        # Get timestamp for window start
        window_start = timezone.now() - timedelta(minutes=time_window)
        
        # Find users with multiple failed logins
        failed_logins = (
            AuditEvent.objects
            .filter(
                timestamp__gte=window_start,
                event_type=AuditEvent.EventType.LOGIN,
                description__contains="failed"
            )
            .values('user__username', 'ip_address')
            .annotate(count=Count('id'))
            .filter(count__gte=threshold)
        )
        
        # Also check security logs for failed logins
        security_failed_logins = (
            SecurityAuditLog.objects
            .filter(
                timestamp__gte=window_start,
                event_type=SecurityAuditLog.EventType.LOGIN_FAILED
            )
            .values('additional_data__username', 'ip_address')
            .annotate(count=Count('id'))
            .filter(count__gte=threshold)
        )
        
        alerts = []
        
        # Process failed logins from audit events
        for login in failed_logins:
            username = login['user__username'] or 'Unknown'
            ip_address = login['ip_address']
            count = login['count']
            
            # Create security alert
            alert = SecurityAlertService.create_security_alert(
                event_type='BRUTE_FORCE_ATTEMPT',
                description=f"Multiple failed login attempts ({count}) for user {username}",
                severity='HIGH',
                ip_address=ip_address,
                additional_data={
                    'username': username,
                    'attempt_count': count,
                    'time_window_minutes': time_window,
                    'source': 'audit_events'
                }
            )
            alerts.append(alert)
            
        # Process failed logins from security logs
        for login in security_failed_logins:
            username = login['additional_data__username'] or 'Unknown'
            ip_address = login['ip_address']
            count = login['count']
            
            # Create security alert
            alert = SecurityAlertService.create_security_alert(
                event_type='BRUTE_FORCE_ATTEMPT',
                description=f"Multiple failed login attempts ({count}) for user {username}",
                severity='HIGH',
                ip_address=ip_address,
                additional_data={
                    'username': username,
                    'attempt_count': count,
                    'time_window_minutes': time_window,
                    'source': 'security_logs'
                }
            )
            alerts.append(alert)
            
        return alerts
    
    @staticmethod
    def _detect_unusual_phi_access():
        """
        Detect unusual patterns of PHI access.
        
        Looks for patterns like:
        - Users accessing records of patients not normally in their care
        - Accessing sensitive records without proper justification
        - Unusual timing or volume of access
        
        Returns:
            list: Security alerts created
        """
        alerts = []
        
        # Time window for analysis (last 24 hours)
        end_time = timezone.now()
        start_time = end_time - timedelta(hours=24)
        
        # 1. Detect users accessing PHI without a documented reason
        access_without_reason = (
            PHIAccessLog.objects
            .filter(
                timestamp__gte=start_time,
                timestamp__lte=end_time,
                reason__in=['', 'No reason provided']
            )
            .values('user')
            .annotate(access_count=Count('id'))
            .filter(access_count__gt=3)  # More than 3 accesses without reason
        )
        
        for item in access_without_reason:
            if not item['user']:
                continue  # Skip anonymous access
   
            try:
                user = User.objects.get(id=item['user'])
                
                alert = SecurityAlertService.create_security_alert(
                    event_type='PERMISSION_VIOLATION',
                    description=f"User {user.username} accessed PHI {item['access_count']} times without providing a reason",
                    severity='MEDIUM',
                    user=user,
                    additional_data={
                        'access_count': item['access_count'],
                        'detection_type': 'missing_reason',
                        'time_period': '24_hours'
                    }
                )
                alerts.append(alert)
            except User.DoesNotExist:
                logger.warning(f"User with ID {item['user']} not found")
        
        # 2. Detect users accessing an unusual number of different patients
        # This requires comparing to typical access patterns for each role
        patient_access_thresholds = {
            'provider': 20,      # Providers typically see a limited number of patients
            'nurse': 30,         # Nurses may see more patients
            'admin': 50,         # Admins may need to access many records
            'researcher': 15,    # Researchers should have limited clinical access
            'caregiver': 5,      # Caregivers should access few patients
        }
        
        unusual_patient_access = []
        
        # Get counts of distinct patients accessed by each user
        users_patient_counts = (
            PHIAccessLog.objects
            .filter(timestamp__gte=start_time, timestamp__lte=end_time)
            .values('user', 'user__role')
            .annotate(patient_count=Count('patient', distinct=True))
        )
        
        # Compare against role-based thresholds
        for item in users_patient_counts:
            if not item['user']:
                continue  # Skip anonymous access
                
            user_role = item['user__role'] or 'unknown'
            threshold = patient_access_thresholds.get(user_role, 15)  # Default threshold
            
            if item['patient_count'] > threshold:
                try:
                    user = User.objects.get(id=item['user'])
                    
                    alert = SecurityAlertService.create_security_alert(
                        event_type='UNUSUAL_ACTIVITY',
                        description=f"User {user.username} ({user_role}) accessed {item['patient_count']} different patients in 24 hours (threshold: {threshold})",
                        severity='MEDIUM',
                        user=user,
                        additional_data={
                            'patient_count': item['patient_count'],
                            'role_threshold': threshold,
                            'user_role': user_role,
                            'detection_type': 'many_patients'
                        }
                    )
                    alerts.append(alert)
                except User.DoesNotExist:
                    logger.warning(f"User with ID {item['user']} not found")
        
        return alerts
    
    @staticmethod
    def _detect_after_hours_access():
        """
        Detect after-hours system access.
        
        Identify PHI access that occurs outside normal business hours
        which could indicate unauthorized access.
        
        Returns:
            list: Security alerts created
        """
        alerts = []
        
        # Get business hours configuration
        business_hours_start = getattr(settings, 'BUSINESS_HOURS_START', 8)  # 8 AM default
        business_hours_end = getattr(settings, 'BUSINESS_HOURS_END', 18)     # 6 PM default
        weekend_days = getattr(settings, 'WEEKEND_DAYS', [5, 6])             # Saturday, Sunday
        
        # Get time window (last 24 hours)
        end_time = timezone.now()
        start_time = end_time - timedelta(hours=24)
        
        # Get PHI access logs
        recent_access = PHIAccessLog.objects.filter(
            timestamp__gte=start_time,
            timestamp__lte=end_time
        )
        
        # Set of users who are expected to have after-hours access
        expected_after_hours_roles = ['admin', 'emergency_provider']
        
        # Group after-hours access by user
        after_hours_by_user = {}
        
        # Examine each access log
        for access in recent_access:
            if not access.user or access.user.role in expected_after_hours_roles:
                continue  # Skip expected after-hours users
                
            access_time = access.timestamp
            is_weekend = access_time.weekday() in weekend_days
            is_after_hours = (access_time.hour < business_hours_start or 
                             access_time.hour >= business_hours_end)
            
            # Check if this is an after-hours access
            if is_weekend or is_after_hours:
                user_id = access.user.id
                
                # Count by user
                if user_id not in after_hours_by_user:
                    after_hours_by_user[user_id] = {
                        'user': access.user,
                        'count': 0,
                        'accesses': []
                    }
                    
                after_hours_by_user[user_id]['count'] += 1
                after_hours_by_user[user_id]['accesses'].append({
                    'time': access_time,
                    'patient_id': str(access.patient.id) if access.patient else None,
                    'record_type': access.record_type,
                    'record_id': access.record_id
                })
        
        # Create alerts for users with significant after-hours access
        for user_id, data in after_hours_by_user.items():
            if data['count'] >= 5:  # Threshold for alerting
                alert = SecurityAlertService.create_security_alert(
                    event_type='AFTER_HOURS_ACCESS',
                    description=f"User {data['user'].username} accessed PHI {data['count']} times outside business hours",
                    severity='MEDIUM',
                    user=data['user'],
                    additional_data={
                        'access_count': data['count'],
                        'access_details': data['accesses'][:10],  # Include first 10 accesses
                        'business_hours': f"{business_hours_start}:00-{business_hours_end}:00",
                        'detection_type': 'after_hours_access'
                    }
                )
                alerts.append(alert)
        
        return alerts
    
    @staticmethod
    def _detect_unusual_ip_addresses():
        """
        Detect access from unusual IP addresses.
        
        Compare current access IP addresses with historical patterns
        to identify potentially unauthorized access.
        
        Returns:
            list: Security alerts created
        """
        alerts = []
        
        # Get time window (last 24 hours for recent, 30 days for historical)
        end_time = timezone.now()
        recent_start = end_time - timedelta(hours=24)
        historical_start = end_time - timedelta(days=30)
        
        # Get recent active users
        recent_users = (
            AuditEvent.objects
            .filter(
                timestamp__gte=recent_start,
                user__isnull=False
            )
            .values_list('user', flat=True)
            .distinct()
        )
        
        for user_id in recent_users:
            # Get historical IP addresses for this user
            historical_ips = (
                AuditEvent.objects
                .filter(
                    user_id=user_id,
                    timestamp__gte=historical_start,
                    timestamp__lt=recent_start,
                    ip_address__isnull=False
                )
                .values_list('ip_address', flat=True)
                .distinct()
            )
            
            # Skip users with no historical data or very few IPs
            if len(historical_ips) < 2:
                continue
                
            # Get recent IP addresses
            recent_ips = (
                AuditEvent.objects
                .filter(
                    user_id=user_id,
                    timestamp__gte=recent_start,
                    ip_address__isnull=False
                )
                .values_list('ip_address', flat=True)
                .distinct()
            )
            
            # Look for IPs in recent activity that weren't in historical data
            new_ips = set(recent_ips) - set(historical_ips)
            
            if new_ips:
                try:
                    user = User.objects.get(id=user_id)
                    
                    alert = SecurityAlertService.create_security_alert(
                        event_type='UNUSUAL_ACTIVITY',
                        description=f"User {user.username} accessed system from {len(new_ips)} new IP addresses",
                        severity='MEDIUM',
                        user=user,
                        additional_data={
                            'new_ip_addresses': list(new_ips),
                            'historical_ip_count': len(historical_ips),
                            'detection_type': 'new_ip_address'
                        }
                    )
                    alerts.append(alert)
                except User.DoesNotExist:
                    logger.warning(f"User with ID {user_id} not found")
        
        return alerts
    
    @staticmethod
    def _detect_high_volume_access():
        """
        Detect high volume access patterns.
        
        Look for users accessing an unusually high number of records in a short time,
        which could indicate unauthorized data exfiltration.
        
        Returns:
            list: Security alerts created
        """
        alerts = []
        
        # Get thresholds from settings
        thresholds = getattr(settings, 'MINIMUM_NECESSARY_THRESHOLDS', {
            'records_per_minute_max': 10,
            'records_per_hour_max': 100,
            'rapid_access_threshold': 50,
        })
        
        # Time windows for analysis
        end_time = timezone.now()
        hour_start = end_time - timedelta(hours=1)
        
        rapid_access = (
            PHIAccessLog.objects
            .filter(timestamp__gte=hour_start)
            .annotate(
                hour=Extract('timestamp', 'hour'),
                day=Extract('timestamp', 'day'),
                month=Extract('timestamp', 'month'),
                year=Extract('timestamp', 'year')
            )
            .values('user', 'hour', 'day', 'month', 'year')
            .annotate(access_count=Count('id'))
            .filter(access_count__gt=thresholds.get('records_per_hour_max', 100))
        )
        
        for access in rapid_access:
            if not access['user']:
                continue
                
            try:
                user = User.objects.get(id=access['user'])
                
                access_date = f"{access['year']}-{access['month']}-{access['day']} {access['hour']}:00"
                
                alert = SecurityAlertService.create_security_alert(
                    event_type='BULK_ACCESS',
                    description=f"User {user.username} accessed {access['access_count']} records in a single hour ({access_date})",
                    severity='HIGH',
                    user=user,
                    additional_data={
                        'access_count': access['access_count'],
                        'timestamp': access_date,
                        'threshold': thresholds.get('records_per_hour_max', 100),
                        'detection_type': 'rapid_access'
                    }
                )
                alerts.append(alert)
            except User.DoesNotExist:
                logger.warning(f"User with ID {access['user']} not found")
        
        return alerts
    
    @staticmethod
    def _detect_vip_patient_access():
        """
        Monitor access to VIP patient records.
        
        For high-profile patients, monitor and alert on all accesses.
        
        Returns:
            list: Security alerts created
        """
        alerts = []
        
        # Get VIP patient list from settings
        vip_patients = getattr(settings, 'VIP_PATIENT_IDS', [])
        
        # Skip if no VIP patients configured
        if not vip_patients:
            return alerts
            
        # Time window for analysis (last 24 hours)
        end_time = timezone.now()
        start_time = end_time - timedelta(hours=24)
        
        # Get access to VIP patient records
        vip_access_logs = PHIAccessLog.objects.filter(
            timestamp__gte=start_time,
            patient_id__in=vip_patients
        )
        
        # Group by user and patient
        vip_access_by_user = {}
        
        for log in vip_access_logs:
            if not log.user:
                continue
                
            user_id = log.user.id
            patient_id = log.patient.id if log.patient else 'unknown'
            
            # Initialize tracking for this user if needed
            if user_id not in vip_access_by_user:
                vip_access_by_user[user_id] = {}
                
            # Initialize tracking for this patient if needed
            if patient_id not in vip_access_by_user[user_id]:
                vip_access_by_user[user_id][patient_id] = {
                    'count': 0,
                    'accesses': []
                }
                
            # Record this access
            vip_access_by_user[user_id][patient_id]['count'] += 1
            vip_access_by_user[user_id][patient_id]['accesses'].append({
                'timestamp': log.timestamp.isoformat(),
                'record_type': log.record_type,
                'record_id': log.record_id,
                'access_type': log.get_access_type_display(),
                'reason': log.reason
            })
        
        # Create alerts for all VIP accesses (can be tuned based on need)
        for user_id, patient_data in vip_access_by_user.items():
            for patient_id, access_data in patient_data.items():
                try:
                    user = User.objects.get(id=user_id)
                    
                    # Always alert for VIP access
                    alert = SecurityAlertService.create_security_alert(
                        event_type='VIP_ACCESS',
                        description=f"User {user.username} accessed VIP patient records {access_data['count']} times",
                        severity='HIGH',  # VIP access is always high priority
                        user=user,
                        additional_data={
                            'patient_id': patient_id,
                            'access_count': access_data['count'],
                            'access_details': access_data['accesses'],
                            'detection_type': 'vip_patient_access'
                        }
                    )
                    alerts.append(alert)
                except User.DoesNotExist:
                    logger.warning(f"User with ID {user_id} not found")
        
        return alerts
