# tasks.py
from django.utils import timezone
from datetime import timedelta
from celery import shared_task
from django.db.models import Q
import logging

from .models import (
    User, PatientProfile, CaregiverRequest, EmergencyAccess,
    ConsentRecord, HIPAADocument
)
from .utils import EmailService, DataRetentionManager, ComplianceReporter

logger = logging.getLogger(__name__)


@shared_task
def check_verification_expirations():
    """
    Check for patients whose identity verification period is expiring.
    Runs daily.
    """
    # Find patients approaching 30-day deadline (5 days warning)
    warning_date = timezone.now() - timedelta(days=25)
    expiry_date = timezone.now() - timedelta(days=30)
    
    # Send warnings to patients approaching deadline
    patients_to_warn = PatientProfile.objects.filter(
        identity_verified=False,
        first_login_date__isnull=False,
        first_login_date__lte=warning_date,
        first_login_date__gt=expiry_date,
        verification_deadline_notified=False
    )
    
    warned_count = 0
    for patient in patients_to_warn:
        try:
            EmailService.send_identity_verification_reminder(patient)
            patient.verification_deadline_notified = True
            patient.save(update_fields=['verification_deadline_notified'])
            warned_count += 1
        except Exception as e:
            logger.error(f"Failed to send verification reminder to {patient.user.email}: {str(e)}")
    
    # Deactivate accounts past deadline
    expired_patients = PatientProfile.objects.filter(
        identity_verified=False,
        first_login_date__isnull=False,
        first_login_date__lte=expiry_date,
        user__is_active=True
    )
    
    deactivated_count = 0
    for patient in expired_patients:
        try:
            # Deactivate user account
            user = patient.user
            user.is_active = False
            user.save(update_fields=['is_active'])
            
            # Send notifications
            EmailService.send_account_deactivation_notice(patient)
            
            # Notify admins
            notify_admins_account_deactivation(patient)
            
            deactivated_count += 1
        except Exception as e:
            logger.error(f"Failed to deactivate account for {patient.user.email}: {str(e)}")
    
    logger.info(
        f"Verification check complete: {warned_count} warnings sent, "
        f"{deactivated_count} accounts deactivated"
    )
    
    return {
        'warnings_sent': warned_count,
        'accounts_deactivated': deactivated_count
    }


@shared_task
def process_expired_caregiver_requests():
    """
    Mark old pending caregiver requests as expired.
    Runs daily.
    """
    expiry_days = 30
    cutoff_date = timezone.now() - timedelta(days=expiry_days)
    
    expired_count = CaregiverRequest.objects.filter(
        status='PENDING',
        requested_at__lt=cutoff_date
    ).update(status='EXPIRED')
    
    logger.info(f"Marked {expired_count} caregiver requests as expired")
    
    return {'expired_count': expired_count}


@shared_task
def send_caregiver_request_reminders():
    """
    Send reminders for pending caregiver requests.
    Runs weekly.
    """
    # Send reminders for requests pending for more than 7 days
    reminder_date = timezone.now() - timedelta(days=7)
    
    pending_requests = CaregiverRequest.objects.filter(
        status='PENDING',
        requested_at__lt=reminder_date,
        reminder_sent=False
    )
    
    reminded_count = 0
    for request in pending_requests:
        try:
            EmailService.send_caregiver_request_notification(
                request.patient,
                request.caregiver
            )
            request.reminder_sent = True
            request.save(update_fields=['reminder_sent'])
            reminded_count += 1
        except Exception as e:
            logger.error(
                f"Failed to send reminder for caregiver request {request.id}: {str(e)}"
            )
    
    logger.info(f"Sent {reminded_count} caregiver request reminders")
    
    return {'reminders_sent': reminded_count}


@shared_task
def review_emergency_access():
    """
    Check for unreviewed emergency access events.
    Runs every 6 hours.
    """
    # Find unreviewed emergency access older than 24 hours
    review_deadline = timezone.now() - timedelta(hours=24)
    
    unreviewed_access = EmergencyAccess.objects.filter(
        reviewed=False,
        requested_at__lt=review_deadline
    )
    
    notification_count = 0
    for access in unreviewed_access:
        try:
            # Re-send notification to compliance team
            EmailService.send_emergency_access_notification(access)
            notification_count += 1
        except Exception as e:
            logger.error(
                f"Failed to send emergency access reminder for {access.id}: {str(e)}"
            )
    
    logger.info(
        f"Emergency access review: {unreviewed_access.count()} unreviewed, "
        f"{notification_count} notifications sent"
    )
    
    return {
        'unreviewed_count': unreviewed_access.count(),
        'notifications_sent': notification_count
    }


@shared_task
def check_password_expiry():
    """
    Check for users with expired passwords.
    Runs daily.
    """
    # Passwords expire after 90 days
    expiry_date = timezone.now() - timedelta(days=90)
    warning_date = timezone.now() - timedelta(days=83)  # 7 day warning
    
    # Find users with expired passwords who are still active
    expired_users = User.objects.filter(
        password_last_changed__lt=expiry_date,
        is_active=True,
        is_approved=True
    ).exclude(role='admin')  # Admins handle their own password policies
    
    # Find users approaching expiry
    warning_users = User.objects.filter(
        password_last_changed__lt=warning_date,
        password_last_changed__gte=expiry_date,
        is_active=True,
        is_approved=True
    ).exclude(role='admin')
    
    # Send warning emails
    warning_count = 0
    for user in warning_users:
        try:
            days_until_expiry = 90 - (timezone.now() - user.password_last_changed).days
            
            # Send warning email
            subject = f"Password Expiring in {days_until_expiry} Days"
            message = f"""
            Hello {user.first_name or user.username},
            
            Your password will expire in {days_until_expiry} days.
            
            Please log in to the Klararety Health Platform and change your password
            to avoid any interruption in service.
            
            Best regards,
            The Klararety Team
            """
            
            EmailService.send_email(subject, message, [user.email])
            warning_count += 1
        except Exception as e:
            logger.error(f"Failed to send password expiry warning to {user.email}: {str(e)}")
    
    logger.info(
        f"Password expiry check: {expired_users.count()} expired, "
        f"{warning_count} warnings sent"
    )
    
    return {
        'expired_count': expired_users.count(),
        'warnings_sent': warning_count
    }


@shared_task
def cleanup_expired_tokens():
    """
    Clean up expired verification and reset tokens.
    Runs daily.
    """
    # Email verification tokens expire after 7 days
    email_token_expiry = timezone.now() - timedelta(days=7)
    
    # Password reset tokens expire after 24 hours
    password_token_expiry = timezone.now() - timedelta(hours=24)
    
    # Clean expired email verification tokens
    email_cleaned = User.objects.filter(
        email_verification_sent_at__lt=email_token_expiry,
        email_verification_token__isnull=False
    ).update(
        email_verification_token=None,
        email_verification_sent_at=None
    )
    
    # Clean expired password reset tokens
    password_cleaned = User.objects.filter(
        reset_password_token_created_at__lt=password_token_expiry,
        reset_password_token__isnull=False
    ).update(
        reset_password_token=None,
        reset_password_token_created_at=None
    )
    
    logger.info(
        f"Token cleanup: {email_cleaned} email tokens, "
        f"{password_cleaned} password tokens cleaned"
    )
    
    return {
        'email_tokens_cleaned': email_cleaned,
        'password_tokens_cleaned': password_cleaned
    }


@shared_task
def generate_compliance_report():
    """
    Generate monthly compliance reports.
    Runs monthly.
    """
    # Generate report for the previous month
    end_date = timezone.now().replace(day=1) - timedelta(days=1)
    start_date = end_date.replace(day=1)
    
    try:
        report = ComplianceReporter.generate_access_report(start_date, end_date)
        
        # Send report to compliance officers
        compliance_users = User.objects.filter(
            role='compliance',
            is_active=True
        )
        
        if compliance_users.exists():
            subject = f"Monthly Compliance Report - {end_date.strftime('%B %Y')}"
            
            # Format report as email
            message = f"""
            Monthly HIPAA Compliance Report
            Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}
            
            Emergency Access Summary:
            - Total Events: {report['emergency_access']['total']}
            - Justified: {report['emergency_access']['justified']}
            - Unjustified: {report['emergency_access']['unjustified']}
            - Pending Review: {report['emergency_access']['pending_review']}
            
            Consent Changes:
            - Total: {report['consent_changes']['total']}
            
            Please log in to the platform for detailed reports.
            """
            
            for user in compliance_users:
                EmailService.send_email(subject, message, [user.email])
        
        logger.info("Monthly compliance report generated and sent")
        
        return {'report_generated': True, 'recipients': compliance_users.count()}
        
    except Exception as e:
        logger.error(f"Failed to generate compliance report: {str(e)}")
        return {'report_generated': False, 'error': str(e)}


@shared_task
def check_document_expirations():
    """
    Check for expiring HIPAA documents.
    Runs weekly.
    """
    # Check for documents expiring in the next 30 days
    expiry_warning = timezone.now().date() + timedelta(days=30)
    
    expiring_documents = HIPAADocument.objects.filter(
        active=True,
        expiration_date__isnull=False,
        expiration_date__lte=expiry_warning,
        expiration_date__gte=timezone.now().date()
    )
    
    if expiring_documents.exists():
        # Notify admins
        admin_users = User.objects.filter(
            Q(is_superuser=True) | Q(role='admin'),
            is_active=True
        )
        
        for admin in admin_users:
            subject = "HIPAA Documents Expiring Soon"
            
            doc_list = "\n".join([
                f"- {doc.title} v{doc.version} (expires {doc.expiration_date})"
                for doc in expiring_documents
            ])
            
            message = f"""
            The following HIPAA documents are expiring soon:
            
            {doc_list}
            
            Please review and update these documents as needed.
            """
            
            EmailService.send_email(subject, message, [admin.email])
    
    logger.info(f"Document expiration check: {expiring_documents.count()} documents expiring soon")
    
    return {'expiring_count': expiring_documents.count()}


@shared_task
def audit_log_maintenance():
    """
    Perform maintenance on audit logs according to retention policy.
    Runs monthly.
    """
    # This is a placeholder - actual implementation depends on audit app
    try:
        # Clean old audit logs based on retention policy
        retention_period = DataRetentionManager.get_retention_period('audit_logs')
        cutoff_date = timezone.now() - timedelta(days=retention_period * 365)
        
        # Archive or delete old logs
        # This would be implemented based on your audit system
        
        logger.info("Audit log maintenance completed")
        return {'success': True}
        
    except Exception as e:
        logger.error(f"Audit log maintenance failed: {str(e)}")
        return {'success': False, 'error': str(e)}


# Helper functions
def notify_admins_account_deactivation(patient_profile):
    """Notify admins when account is deactivated for verification expiry."""
    admin_users = User.objects.filter(
        Q(is_superuser=True) | Q(role='admin'),
        is_active=True
    )
    
    if not admin_users.exists():
        return
    
    user = patient_profile.user
    subject = "Patient Account Automatically Deactivated"
    
    message = f"""
    A patient account has been automatically deactivated due to identity verification expiry.
    
    Patient: {user.get_full_name() or user.username}
    Email: {user.email}
    Account Created: {user.date_joined.strftime('%Y-%m-%d')}
    First Login: {patient_profile.first_login_date.strftime('%Y-%m-%d') if patient_profile.first_login_date else 'Never'}
    
    The patient has been notified to contact support for reactivation.
    
    This is an automated notification from the Klararety Health Platform.
    """
    
    for admin in admin_users:
        try:
            EmailService.send_email(subject, message, [admin.email])
        except Exception as e:
            logger.error(f"Failed to send admin notification to {admin.email}: {str(e)}")


@shared_task
def send_admin_notifications():
    """
    Send daily summary notifications to admins.
    Runs daily.
    """
    from django.db.models import Count
    
    # Get pending approvals count
    pending_users = User.objects.filter(
        is_approved=False,
        is_staff=False
    ).exclude(role='admin').count()
    
    # Get pending caregiver requests
    pending_caregiver_requests = CaregiverRequest.objects.filter(
        status='PENDING'
    ).count()
    
    # Get unreviewed emergency access
    unreviewed_emergency = EmergencyAccess.objects.filter(
        reviewed=False
    ).count()
    
    if pending_users > 0 or pending_caregiver_requests > 0 or unreviewed_emergency > 0:
        admin_users = User.objects.filter(
            Q(is_superuser=True) | Q(role='admin'),
            is_active=True
        )
        
        for admin in admin_users:
            subject = "Daily Admin Notification - Pending Actions"
            
            message = f"""
            Daily summary of pending actions requiring administrator attention:
            
            • Pending User Approvals: {pending_users}
            • Pending Caregiver Requests: {pending_caregiver_requests}
            • Unreviewed Emergency Access: {unreviewed_emergency}
            
            Please log in to the admin panel to review and take action.
            
            This is an automated daily notification from the Klararety Health Platform.
            """
            
            try:
                EmailService.send_email(subject, message, [admin.email])
            except Exception as e:
                logger.error(f"Failed to send daily notification to {admin.email}: {str(e)}")
    
    logger.info("Daily admin notifications completed")
    
    return {
        'pending_users': pending_users,
        'pending_caregiver_requests': pending_caregiver_requests,
        'unreviewed_emergency': unreviewed_emergency
    }


@shared_task
def auto_end_expired_emergency_access():
    """
    Automatically end expired emergency access sessions.
    Runs hourly.
    """
    from .utils import EmergencyAccessManager
    
    count = EmergencyAccessManager.auto_end_expired_access()
    
    logger.info(f"Auto-ended {count} expired emergency access sessions")
    
    return {'expired_sessions_ended': count}
