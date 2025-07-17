# signals.py
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.conf import settings
from django.utils import timezone
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

from .models import (
    User, PatientProfile, ConsentRecord, CaregiverRequest,
    EmergencyAccess
)
from .utils import EmailService


@receiver(post_save, sender=User)
def handle_user_post_save(sender, instance, created, **kwargs):
    """
    Handle user post-save events.
    Note: Profiles are created during approval, not on user creation.
    """
    if created:
        # Send notification to admins for non-admin users
        if not instance.is_staff and instance.role != 'admin':
            notify_admins_new_registration(instance)
        
        # If user is pre-approved (e.g., admin creating user), create profile
        if instance.is_approved and not instance.profile_created:
            instance.create_profile()


@receiver(pre_save, sender=User)
def handle_user_pre_save(sender, instance, **kwargs):
    """Handle user pre-save events."""
    # Ensure username equals email
    if instance.email:
        instance.username = instance.email
    
    # Track approval status change
    if instance.pk:
        try:
            old_instance = User.objects.get(pk=instance.pk)
            
            # Check if user is being approved
            if not old_instance.is_approved and instance.is_approved:
                # Set approval timestamp if not already set
                if not instance.approved_at:
                    instance.approved_at = timezone.now()
                
                # Create profile after approval
                if not instance.profile_created:
                    # This will be called after save
                    pass
                    
        except User.DoesNotExist:
            pass


@receiver(post_save, sender=PatientProfile)
def track_patient_consent_changes(sender, instance, created, **kwargs):
    """Track consent changes for patients."""
    if not created:
        # Get the old instance to compare
        try:
            old_instance = PatientProfile.objects.get(pk=instance.pk)
            
            # Check medication adherence consent change
            if old_instance.medication_adherence_monitoring_consent != instance.medication_adherence_monitoring_consent:
                ConsentRecord.objects.create(
                    user=instance.user,
                    consent_type='MEDICATION_MONITORING',
                    consented=instance.medication_adherence_monitoring_consent
                )
                
                if instance.medication_adherence_monitoring_consent:
                    instance.medication_adherence_consent_date = timezone.now()
            
            # Check vitals monitoring consent change
            if old_instance.vitals_monitoring_consent != instance.vitals_monitoring_consent:
                ConsentRecord.objects.create(
                    user=instance.user,
                    consent_type='VITALS_MONITORING',
                    consented=instance.vitals_monitoring_consent
                )
                
                if instance.vitals_monitoring_consent:
                    instance.vitals_monitoring_consent_date = timezone.now()
            
            # Check research participation consent change
            if old_instance.research_participation_consent != instance.research_participation_consent:
                ConsentRecord.objects.create(
                    user=instance.user,
                    consent_type='RESEARCH_PARTICIPATION',
                    consented=instance.research_participation_consent
                )
                
                if instance.research_participation_consent:
                    instance.research_consent_date = timezone.now()
                    
        except PatientProfile.DoesNotExist:
            pass


@receiver(post_save, sender=CaregiverRequest)
def handle_caregiver_request(sender, instance, created, **kwargs):
    """Handle caregiver request notifications."""
    if created and not instance.patient_notified:
        # Send notification to patient
        EmailService.send_caregiver_request_notification(
            instance.patient,
            instance.caregiver
        )
        
        # Mark as notified
        instance.patient_notified = True
        instance.save(update_fields=['patient_notified'])
        
        # Send WebSocket notification if available
        try:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"user_{instance.patient.id}",
                {
                    "type": "notification",
                    "message": f"New caregiver request from {instance.caregiver.get_full_name() or instance.caregiver.email}"
                }
            )
        except:
            pass  # WebSocket notification is optional


def notify_admins_new_registration(user):
    """Notify admins of new user registration via WebSocket."""
    try:
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            "admin_notifications",
            {
                "type": "notify.registration",
                "message": f"New {user.get_role_display()} registration: {user.email}",
                "user_id": user.id,
                "timestamp": timezone.now().isoformat()
            }
        )
    except:
        # WebSocket notification is optional
        pass


# Signal to clean up expired tokens
@receiver(pre_save, sender=User)
def clean_expired_tokens(sender, instance, **kwargs):
    """Clean up expired verification and reset tokens."""
    if instance.pk:
        # Clean expired email verification token (older than 7 days)
        if instance.email_verification_sent_at:
            if (timezone.now() - instance.email_verification_sent_at).days > 7:
                instance.email_verification_token = None
                instance.email_verification_sent_at = None
        
        # Clean expired password reset token (older than 24 hours)
        if instance.reset_password_token_created_at:
            if (timezone.now() - instance.reset_password_token_created_at).total_seconds() > 86400:
                instance.reset_password_token = None
                instance.reset_password_token_created_at = None

@receiver(post_save, sender=User)
def handle_user_registration_data(sender, instance, created, **kwargs):
    """Handle storing registration data for later profile creation."""
    if created and not instance.is_approved:
        # Store registration data is handled in the serializer
        # This signal just ensures proper notification flow
        pass

@receiver(post_save, sender=User)
def handle_user_approval(sender, instance, **kwargs):
    """Handle user approval and profile creation."""
    if instance.is_approved and not instance.profile_created:
        # Get stored registration data
        from .utils import RegistrationDataManager
        registration_data = RegistrationDataManager.get_registration_data(instance)
        
        # Store data temporarily on instance for profile creation
        if registration_data:
            instance._registration_data = registration_data
        
        # Create profile
        instance.create_profile()
        
        # Clear stored registration data
        RegistrationDataManager.clear_registration_data(instance)
        
        # Send approval notification
        try:
            from .utils import EmailService
            EmailService.send_approval_email(instance)
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to send approval email to {instance.email}: {str(e)}")

@receiver(post_save, sender=PatientProfile)
def handle_patient_identity_verification(sender, instance, **kwargs):
    """Handle patient identity verification status changes."""
    if instance.identity_verified:
        # Log verification event
        from .utils import SecurityLogger
        SecurityLogger.log_event(
            user=instance.user,
            event_type="IDENTITY_VERIFIED",
            description=f"Identity verified using {instance.identity_verification_method}"
        )
        
        # Create consent record for identity verification
        ConsentRecord.objects.get_or_create(
            user=instance.user,
            consent_type='IDENTITY_VERIFICATION',
            defaults={
                'consented': True,
                'document_version': 'v1.0'
            }
        )

@receiver(post_save, sender=EmergencyAccess)
def handle_emergency_access_created(sender, instance, created, **kwargs):
    """Handle emergency access creation."""
    if created:
        # Send immediate notifications
        from .utils import EmergencyAccessManager
        EmergencyAccessManager.notify_compliance_team(instance)
        
        # Log security event
        from .utils import SecurityLogger
        SecurityLogger.log_event(
            user=instance.requester,
            event_type="EMERGENCY_ACCESS_INITIATED",
            description=f"Emergency access initiated: {instance.get_reason_display()}",
            ip_address=instance.ip_address
        )

@receiver(post_save, sender=CaregiverRequest)
def handle_caregiver_request_status_change(sender, instance, **kwargs):
    """Handle caregiver request status changes."""
    if instance.status == 'APPROVED':
        # Create patient-caregiver authorization
        try:
            from .models import PatientAuthorizedCaregiver
            PatientAuthorizedCaregiver.objects.get_or_create(
                patient=instance.patient.patient_profile,
                caregiver=instance.caregiver,
                defaults={
                    'access_level': 'VIEW_ONLY',
                    'authorized_by': instance.patient
                }
            )
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to create caregiver authorization: {str(e)}")
    
    elif instance.status == 'DENIED':
        # Log denial for audit purposes
        from .utils import SecurityLogger
        SecurityLogger.log_event(
            user=instance.patient,
            event_type="CAREGIVER_REQUEST_DENIED",
            description=f"Denied caregiver request from {instance.caregiver.email}"
        )

@receiver(post_save, sender=ConsentRecord)
def handle_consent_record_created(sender, instance, created, **kwargs):
    """Handle consent record creation for audit trails."""
    if created:
        # Log consent change for compliance
        from .utils import HIPAAComplianceManager
        HIPAAComplianceManager.generate_audit_trail(
            user=instance.user,
            action="CONSENT_RECORDED",
            details={
                'consent_type': instance.consent_type,
                'consented': instance.consented,
                'document_version': instance.document_version
            }
        )

# Signal to clean up expired emergency access
from django.db.models.signals import post_migrate

@receiver(post_migrate)
def setup_periodic_tasks(sender, **kwargs):
    """Setup periodic tasks after migration."""
    if sender.name == 'users':
        try:
            from django_celery_beat.models import PeriodicTask, CrontabSchedule
            import json
            
            # Create schedule for daily admin notifications
            schedule, created = CrontabSchedule.objects.get_or_create(
                minute=0,
                hour=8,
                day_of_week='*',
                day_of_month='*',
                month_of_year='*',
            )
            
            PeriodicTask.objects.get_or_create(
                crontab=schedule,
                name='Daily Admin Notifications',
                task='users.tasks.send_admin_notifications',
            )
            
            # Create schedule for hourly emergency access cleanup
            hourly_schedule, created = CrontabSchedule.objects.get_or_create(
                minute=0,
                hour='*',
                day_of_week='*',
                day_of_month='*',
                month_of_year='*',
            )
            
            PeriodicTask.objects.get_or_create(
                crontab=hourly_schedule,
                name='Auto End Expired Emergency Access',
                task='users.tasks.auto_end_expired_emergency_access',
            )
            
        except ImportError:
            # django-celery-beat not installed
            pass
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to setup periodic tasks: {str(e)}")

