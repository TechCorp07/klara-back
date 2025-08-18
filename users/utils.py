# utils.py
import logging
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.utils import timezone
from django.db.models import Q


class EmailService:
    """Centralized email service for all email communications."""
    
    @staticmethod
    def send_email(subject, message, recipient_list, html_message=None, fail_silently=False):
        """Base method for sending emails."""
        return send_mail(
            subject=subject,
            message=message,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=recipient_list,
            html_message=html_message,
            fail_silently=fail_silently
        )
    
    @classmethod
    def send_approval_email(cls, user):
        """Send account approval notification."""
        subject = "Your Klararety Health Platform Account has been Approved"
        
        message = f"""
        Hello {user.first_name or user.username},
        
        Your account on the Klararety Health Platform has been approved. You can now log in using your credentials.
        
        Role: {user.get_role_display()}
        Username: {user.username}
        
        If you haven't verified your email yet, please do so after logging in.
        
        Login at: {settings.FRONTEND_URL}/login
        
        Thank you for joining the Klararety Health Platform.
        
        Best regards,
        The Klararety Team
        """
        
        cls.send_email(subject, message, [user.email])
    
    @classmethod
    def send_admin_notification_new_user(cls, new_user):
        """Notify admins of new user registration."""
        from .models import User
        
        admin_emails = User.objects.filter(
            role='admin',
            is_active=True
        ).values_list('email', flat=True)
        
        if not admin_emails:
            return
        
        subject = f"New {new_user.get_role_display()} Registration Requires Approval"
        
        message = f"""
        A new user has registered and requires approval:
        
        Name: {new_user.get_full_name() or new_user.username}
        Email: {new_user.email}
        Role: {new_user.get_role_display()}
        Registration Date: {new_user.date_joined.strftime('%Y-%m-%d %H:%M')}
        
        Please review and approve or deny this registration at:
        {settings.FRONTEND_URL}/admin/pending-approvals
        
        This is an automated message from the Klararety Health Platform.
        """
        
        cls.send_email(subject, message, list(admin_emails))
    
    @classmethod
    def send_caregiver_request_notification(cls, patient, caregiver):
        """Notify patient of caregiver request."""
        subject = "Caregiver Authorization Request"
        
        message = f"""
        Hello {patient.first_name or patient.username},
        
        {caregiver.get_full_name() or caregiver.email} has requested to be authorized as your caregiver.
        
        Role: {caregiver.get_role_display()}
        Email: {caregiver.email}
        
        Please log in to your account to approve or deny this request:
        {settings.FRONTEND_URL}/profile/caregiver-requests
        
        For your security, only approve caregivers you trust with your health information.
        
        Best regards,
        The Klararety Team
        """
        
        cls.send_email(subject, message, [patient.email])
    
    @classmethod
    def send_caregiver_approval(cls, caregiver, patient):
        """Notify caregiver of approval."""
        subject = "Caregiver Authorization Approved"
        
        message = f"""
        Hello {caregiver.first_name or caregiver.username},
        
        Your request to be a caregiver for {patient.get_full_name() or patient.email} has been approved.
        
        You now have access to their health information based on the permissions granted.
        
        Please log in to access patient information:
        {settings.FRONTEND_URL}/login
        
        Remember to handle all patient information in accordance with HIPAA regulations.
        
        Best regards,
        The Klararety Team
        """
        
        cls.send_email(subject, message, [caregiver.email])
    
    @classmethod
    def send_caregiver_denial(cls, caregiver, patient, reason=''):
        """Notify caregiver of denial."""
        subject = "Caregiver Authorization Request Denied"
        
        message = f"""
        Hello {caregiver.first_name or caregiver.username},
        
        Your request to be a caregiver for {patient.get_full_name() or patient.email} has been denied.
        {f'Reason: {reason}' if reason else ''}
        
        If you believe this is an error, please contact the patient directly.
        
        Best regards,
        The Klararety Team
        """
        
        cls.send_email(subject, message, [caregiver.email])
    
    @classmethod
    def send_password_reset_email(cls, user, token):
        """Send password reset email."""
        subject = "Reset Your Klararety Health Platform Password"
        
        reset_url = f"{settings.FRONTEND_URL}/reset-password/{token}/"
        
        message = f"""
        Hello {user.first_name or user.username},
        
        You have requested to reset your password.
        
        Please click the following link to reset your password:
        {reset_url}
        
        This link will expire in 24 hours.
        
        If you did not request this password reset, please ignore this email.
        
        Best regards,
        The Klararety Team
        """
        
        cls.send_email(subject, message, [user.email])
    
    @classmethod
    def send_email_verification_email(cls, user, token):
        """Send email verification."""
        subject = "Verify Your Email for Klararety Health Platform"
        
        verification_url = f"{settings.FRONTEND_URL}/verify-email/{token}/"
        
        message = f"""
        Hello {user.first_name or user.username},
        
        Thank you for registering with the Klararety Health Platform.
        
        Please click the following link to verify your email address:
        {verification_url}
        
        If you did not create an account with us, please ignore this email.
        
        Best regards,
        The Klararety Team
        """
        
        cls.send_email(subject, message, [user.email])
    
    @staticmethod
    def send_2fa_backup_email(user, backup_code):
        """Send 2FA backup verification code via email."""
        subject = f"{settings.PLATFORM_NAME} - Account Verification Code"
        
        context = {
            'user': user,
            'backup_code': backup_code,
            'platform_name': settings.PLATFORM_NAME,
            'expires_minutes': 10,
        }
        
        html_content = render_to_string('emails/2fa_backup_code.html', context)
        text_content = f"""
    {settings.PLATFORM_NAME} - Account Verification

    Hello {user.get_full_name() or user.email},

    Your verification code is: {backup_code}

    This code will expire in 10 minutes.

    If you didn't request this code, please contact our support team immediately.

    Best regards,
    {settings.PLATFORM_NAME} Security Team
        """
        
        send_mail(
            subject=subject,
            message=text_content,
            html_message=html_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
    
    @classmethod
    def send_emergency_access_notification(cls, emergency_access):
        """Notify compliance of emergency access."""
        from .models import User
        
        compliance_emails = User.objects.filter(
            role='compliance',
            is_active=True
        ).values_list('email', flat=True)
        
        if not compliance_emails:
            return
        
        subject = "URGENT: Emergency PHI Access Event"
        
        message = f"""
        An emergency PHI access has been initiated.
        
        Requester: {emergency_access.requester.get_full_name()} ({emergency_access.requester.email})
        Role: {emergency_access.requester.get_role_display()}
        Time: {emergency_access.requested_at.strftime('%Y-%m-%d %H:%M:%S')}
        Reason: {emergency_access.get_reason_display()}
        Details: {emergency_access.detailed_reason}
        
        This event requires review according to HIPAA emergency access procedures.
        
        Please log in to review: {settings.FRONTEND_URL}/compliance/emergency-access
        
        This is an automated notification from the Klararety Health Platform.
        """
        
        cls.send_email(subject, message, list(compliance_emails))
    
    @classmethod
    def send_admin_credentials(cls, admin_user, password):
        """Send credentials to newly created admin."""
        subject = "Your Klararety Health Platform Admin Account"
        
        message = f"""
        Hello {admin_user.first_name or admin_user.username},
        
        An administrator account has been created for you on the Klararety Health Platform.
        
        Username: {admin_user.username}
        Temporary Password: {password}
        
        Please log in and change your password immediately:
        {settings.FRONTEND_URL}/login
        
        As an administrator, you have access to approve new users and manage the platform.
        Please handle this responsibility with care.
        
        Best regards,
        The Klararety Team
        """
        
        cls.send_email(subject, message, [admin_user.email])
    
    @classmethod
    def send_identity_verification_reminder(cls, patient_profile):
        """Send reminder about identity verification deadline."""
        user = patient_profile.user
        days_left = patient_profile.days_until_verification_required()
        
        subject = f"ACTION REQUIRED: Verify Your Identity - {days_left} Days Remaining"
        
        message = f"""
        Hello {user.first_name or user.username},
        
        This is a reminder that you need to verify your identity within {days_left} days 
        to continue using your Klararety Health Platform account.
        
        To verify your identity, please log in and complete the verification process:
        {settings.FRONTEND_URL}/profile/verify-identity
        
        If your account is not verified by the deadline, it will be automatically deactivated.
        
        Thank you for your attention to this important security requirement.
        
        Best regards,
        The Klararety Team
        """
        
        cls.send_email(subject, message, [user.email])

    @classmethod
    def send_admin_notification_pending_approvals(cls):
        """Send notification about pending approvals to admins."""
        from .models import User
        
        pending_count = User.objects.filter(
            is_approved=False,
            is_staff=False
        ).exclude(role='admin').count()
        
        if pending_count == 0:
            return
        
        admin_emails = User.objects.filter(
            Q(role='admin') | Q(is_superuser=True),
            is_active=True
        ).values_list('email', flat=True)
        
        if not admin_emails:
            return
        
        subject = f"Pending User Approvals - {pending_count} users awaiting review"
        
        message = f"""
        There are currently {pending_count} users awaiting approval on the Klararety Health Platform.
        
        Please log in to the admin panel to review pending registrations:
        {settings.FRONTEND_URL}/admin/pending-approvals
        
        This is an automated notification from the Klararety Health Platform.
        """
        
        cls.send_email(subject, message, list(admin_emails))
        
    @classmethod
    def send_account_deactivation_notice(cls, patient_profile):
        """Notify about account deactivation."""
        user = patient_profile.user
        
        subject = "Account Deactivated - Identity Verification Required"
        
        message = f"""
        Hello {user.first_name or user.username},
        
        Your Klararety Health Platform account has been deactivated because the 30-day 
        period for identity verification has expired.
        
        To reactivate your account, please contact our support team at:
        {settings.SUPPORT_EMAIL}
        
        Thank you for your understanding.
        
        Best regards,
        The Klararety Team
        """
        
        cls.send_email(subject, message, [user.email])
    
    @classmethod
    def send_denial_email(cls, user, reason):
        """Send account denial notification."""
        subject = "Account Application Denied - Klararety Health Platform"
        
        message = f"""
        Hello {user.first_name or user.username},
        
        We regret to inform you that your application for the Klararety Health Platform has been denied.
        
        Reason: {reason}
        
        If you believe this decision was made in error, please contact our support team.
        
        Thank you for your interest in the Klararety Health Platform.
        
        Best regards,
        The Klararety Team
        """
        
        cls.send_email(subject, message, [user.email])


class SecurityLogger:
    """Centralized security event logging."""
    
    logger = logging.getLogger('security')
    
    @classmethod
    def log_event(cls, user, event_type, description, ip_address='', user_agent='', **kwargs):
        """Log security event to audit system."""
        try:
            # Try to use the audit app if available
            from audit.models import SecurityAuditLog
            
            SecurityAuditLog.objects.create(
                user=user,
                event_type=event_type,
                description=description,
                ip_address=ip_address,
                user_agent=user_agent,
                **kwargs
            )
        except ImportError:
            # Fallback to standard logging
            cls.logger.info(
                f"Security Event: {event_type} | "
                f"User: {user.username if user else 'Anonymous'} | "
                f"Description: {description} | "
                f"IP: {ip_address}"
            )
        except Exception as e:
            # Log the error but don't fail the operation
            cls.logger.error(f"Failed to log security event: {str(e)}")


class DataRetentionManager:
    """Manage HIPAA-compliant data retention."""
    
    @staticmethod
    def get_retention_period(data_type):
        """Get retention period for different data types."""
        retention_periods = {
            'audit_logs': 6,  # 6 years
            'consent_records': 6,  # 6 years
            'medical_records': 6,  # 6 years
            'email_logs': 2,  # 2 years
            'session_data': 0.5,  # 6 months
        }
        return retention_periods.get(data_type, 6)  # Default 6 years
    
    @classmethod
    def clean_expired_data(cls):
        """Clean data that has exceeded retention period."""
        from datetime import timedelta
        from .models import ConsentRecord, EmergencyAccess
        
        # Example: Clean old session data
        cutoff_date = timezone.now() - timedelta(days=180)  # 6 months
        
        # This would be expanded to clean various data types
        # based on HIPAA retention requirements
        pass


class ComplianceReporter:
    """Generate compliance reports."""
    
    @staticmethod
    def generate_access_report(start_date, end_date):
        """Generate PHI access report for compliance."""
        from .models import EmergencyAccess, ConsentRecord
        
        report = {
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'emergency_access': {
                'total': EmergencyAccess.objects.filter(
                    requested_at__range=(start_date, end_date)
                ).count(),
                'justified': EmergencyAccess.objects.filter(
                    requested_at__range=(start_date, end_date),
                    access_justified=True
                ).count(),
                'unjustified': EmergencyAccess.objects.filter(
                    requested_at__range=(start_date, end_date),
                    access_justified=False
                ).count(),
                'pending_review': EmergencyAccess.objects.filter(
                    requested_at__range=(start_date, end_date),
                    reviewed=False
                ).count()
            },
            'consent_changes': {
                'total': ConsentRecord.objects.filter(
                    signature_timestamp__range=(start_date, end_date)
                ).count(),
                'by_type': {}
            }
        }
        
        # Add consent breakdown by type
        for consent_type, label in ConsentRecord.CONSENT_TYPES:
            count = ConsentRecord.objects.filter(
                signature_timestamp__range=(start_date, end_date),
                consent_type=consent_type
            ).count()
            report['consent_changes']['by_type'][consent_type] = count
        
        return report


class RegistrationDataManager:
    """Manage temporary registration data storage."""
    
    @staticmethod
    def store_registration_data(user, profile_data):
        """Store profile data temporarily until approval."""
        from .models import TemporaryRegistrationData
        
        temp_data, created = TemporaryRegistrationData.objects.get_or_create(
            user=user,
            defaults={'data': profile_data}
        )
        
        if not created:
            temp_data.data = profile_data
            temp_data.save()
        
        return temp_data
    
    @staticmethod
    def get_registration_data(user):
        """Retrieve stored registration data."""
        from .models import TemporaryRegistrationData
        
        try:
            temp_data = TemporaryRegistrationData.objects.get(user=user)
            return temp_data.data
        except TemporaryRegistrationData.DoesNotExist:
            return {}
    
    @staticmethod
    def clear_registration_data(user):
        """Clear stored registration data after profile creation."""
        from .models import TemporaryRegistrationData
        
        TemporaryRegistrationData.objects.filter(user=user).delete()


class IdentityVerificationManager:
    """Manage identity verification processes."""
    
    VERIFICATION_METHODS = [
        ('E_SIGNATURE', 'Electronic Signature'),
        ('PROVIDER_VERIFICATION', 'Healthcare Provider Verification'),
        ('DOCUMENT_UPLOAD', 'Document Upload'),
        ('VIDEO_VERIFICATION', 'Video Verification'),
    ]
    
    @staticmethod
    def initiate_verification(user, method='E_SIGNATURE'):
        """Initiate identity verification process."""
        if user.role != 'patient':
            return False
        
        if not hasattr(user, 'patient_profile'):
            return False
        
        profile = user.patient_profile
        
        if method == 'E_SIGNATURE':
            # For e-signature verification, we just need to track that
            # the user has completed the e-signature process
            profile.identity_verification_method = method
            profile.save()
            return True
        
        return False
    
    @staticmethod
    def complete_verification(user, method='E_SIGNATURE'):
        """Complete identity verification."""
        if user.role != 'patient':
            return False
        
        if not hasattr(user, 'patient_profile'):
            return False
        
        profile = user.patient_profile
        profile.verify_identity(method=method)
        
        # Log verification
        SecurityLogger.log_event(
            user=user,
            event_type="IDENTITY_VERIFIED",
            description=f"Identity verified using {method}"
        )
        
        return True


class HIPAAComplianceManager:
    """Manage HIPAA compliance requirements."""
    
    @staticmethod
    def check_consent_requirements(user):
        """Check if user has completed all required consent processes."""
        required_consents = {
            'terms_accepted': user.terms_accepted,
            'hipaa_privacy_acknowledged': user.hipaa_privacy_acknowledged,
        }
        
        # Role-specific consent requirements
        if user.role == 'caregiver':
            required_consents['caregiver_authorization_acknowledged'] = user.caregiver_authorization_acknowledged
        
        elif user.role in ['pharmco', 'researcher']:
            required_consents['phi_handling_acknowledged'] = user.phi_handling_acknowledged
        
        return all(required_consents.values()), required_consents
    
    @staticmethod
    def get_missing_documents(user):
        """Get list of HIPAA documents user hasn't signed."""
        from .models import HIPAADocument, ConsentRecord
        
        # Get all active documents
        active_docs = HIPAADocument.objects.filter(active=True)
        
        missing_docs = []
        for doc in active_docs:
            # Check if user has signed this document type
            signed = ConsentRecord.objects.filter(
                user=user,
                consent_type=f'DOC_{doc.document_type}',
                document_version=doc.version,
                revoked=False
            ).exists()
            
            if not signed:
                missing_docs.append(doc)
        
        return missing_docs
    
    @staticmethod
    def generate_audit_trail(user, action, details=None):
        """Generate audit trail entry for HIPAA compliance."""
        try:
            # Try to use audit system if available
            from audit.models import AuditLog
            
            AuditLog.objects.create(
                user=user,
                action=action,
                details=details or {},
                timestamp=timezone.now()
            )
        except ImportError:
            # Fallback to security logger
            SecurityLogger.log_event(
                user=user,
                event_type="COMPLIANCE_AUDIT",
                description=f"{action}: {details}"
            )


# Add emergency access utilities
class EmergencyAccessManager:
    """Manage emergency break-glass access procedures."""
    
    @staticmethod
    def validate_emergency_request(requester, reason, patient_identifier):
        """Validate emergency access request."""
        # Check if requester has permission to request emergency access
        if requester.role not in ['provider', 'admin', 'compliance']:
            return False, "Unauthorized role for emergency access"
        
        # Validate reason
        from .models import EmergencyAccess
        valid_reasons = [choice[0] for choice in EmergencyAccess.REASON_CHOICES]
        if reason not in valid_reasons:
            return False, "Invalid emergency reason"
        
        # Check for rate limiting (prevent abuse)
        recent_requests = EmergencyAccess.objects.filter(
            requester=requester,
            requested_at__gt=timezone.now() - timezone.timedelta(hours=1)
        ).count()
        
        if recent_requests >= 3:
            return False, "Too many emergency access requests in the last hour"
        
        return True, "Valid request"
    
    @staticmethod
    def auto_end_expired_access():
        """Automatically end emergency access sessions after 4 hours."""
        from .models import EmergencyAccess
        
        expired_sessions = EmergencyAccess.objects.filter(
            access_ended_at__isnull=True,
            requested_at__lt=timezone.now() - timezone.timedelta(hours=4)
        )
        
        count = 0
        for session in expired_sessions:
            session.end_access("Automatically ended after 4 hours")
            count += 1
        
        return count
    
    @staticmethod
    def notify_compliance_team(emergency_access):
        """Send immediate notification to compliance team."""
        from .models import User
        
        compliance_users = User.objects.filter(
            role='compliance',
            is_active=True
        )
        
        for user in compliance_users:
            EmailService.send_emergency_access_notification(emergency_access)

