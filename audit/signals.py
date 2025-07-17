from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth import user_logged_in, user_logged_out, user_login_failed
from django.contrib.auth import get_user_model
from django.conf import settings
from .models import AuditEvent, SecurityAuditLog

User = get_user_model()


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    """Log successful user login."""
    AuditEvent.objects.create(
        user=user,
        event_type=AuditEvent.EventType.LOGIN,
        resource_type='user',
        resource_id=str(user.id),
        description=f"User {user.username} logged in",
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    """Log user logout."""
    if user:
        AuditEvent.objects.create(
            user=user,
            event_type=AuditEvent.EventType.LOGOUT,
            resource_type='user',
            resource_id=str(user.id),
            description=f"User {user.username} logged out",
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )


@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, request, **kwargs):
    """Log failed login attempts."""
    username = credentials.get('username', '')
    
    # Extract user agent safely
    if request is not None:
        user_agent = request.META.get('HTTP_USER_AGENT', '')
    else:
        user_agent = 'Unknown'

    # Create security audit log for failed login
    SecurityAuditLog.objects.create(
        user=None,  # No user since login failed
        event_type=SecurityAuditLog.EventType.LOGIN_FAILED,
        description=f"Failed login attempt for username: {username}",
        severity=SecurityAuditLog.Severity.MEDIUM,
        ip_address=get_client_ip(request),
        user_agent=user_agent
    )

    
    # Check for multiple failed logins from the same IP
    if getattr(settings, 'AUDIT_TRACK_FAILED_LOGINS', True):
        ip_address = get_client_ip(request)
        recent_failures = SecurityAuditLog.objects.filter(
            event_type=SecurityAuditLog.EventType.LOGIN_FAILED,
            ip_address=ip_address,
            timestamp__gte=get_time_threshold()
        ).count()
        
        # If threshold exceeded, log a brute force attempt
        threshold = getattr(settings, 'AUDIT_FAILED_LOGIN_THRESHOLD', 5)
        if recent_failures >= threshold:
            SecurityAuditLog.objects.create(
                user=None,
                event_type=SecurityAuditLog.EventType.BRUTE_FORCE_ATTEMPT,
                description=f"Possible brute force attack detected: {recent_failures} failed login attempts from IP {ip_address}",
                severity=SecurityAuditLog.Severity.HIGH,
                ip_address=ip_address,
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )


@receiver(post_save, sender=User)
def log_user_changes(sender, instance, created, **kwargs):
    """Log user creation and changes."""
    if created:
        AuditEvent.objects.create(
            user=None,  # System action or admin who created the user
            event_type=AuditEvent.EventType.CREATE,
            resource_type='user',
            resource_id=str(instance.id),
            description=f"User {instance.username} was created"
        )
    else:
        # We don't log every update since this can be noisy
        # Consider adding more targeted signals for important changes
        pass


@receiver(post_delete, sender=User)
def log_user_deletion(sender, instance, **kwargs):
    """Log user deletion."""
    AuditEvent.objects.create(
        user=None,  # System action or admin who deleted the user
        event_type=AuditEvent.EventType.DELETE,
        resource_type='user',
        resource_id=str(instance.id),
        description=f"User {instance.username} was deleted"
    )


def get_client_ip(request):
    """Get client IP address from request."""
    if not request:
        return None
        
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_time_threshold():
    """Get time threshold for checking failed login attempts."""
    from django.utils import timezone
    from datetime import timedelta
    
    minutes = getattr(settings, 'AUDIT_FAILED_LOGIN_WINDOW_MINUTES', 15)
    return timezone.now() - timedelta(minutes=minutes)
