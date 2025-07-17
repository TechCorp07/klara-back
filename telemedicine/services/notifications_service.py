import logging
from django.conf import settings
from django.utils import timezone
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)

class NotificationException(Exception):
    """Exception for notification errors."""
    pass


def send_appointment_reminder(appointment):
    """
    Send appointment reminder to the patient.
    
    Args:
        appointment: Appointment object to send reminder for
    
    Returns:
        bool: True if notification was sent successfully
    
    Raises:
        NotificationException: If sending fails
    """
    try:
        if not appointment.patient.email:
            logger.warning(f"Cannot send reminder - no email for patient {appointment.patient.id}")
            return False
            
        # Check if appointment is suitable for reminder
        if appointment.status not in ['scheduled', 'confirmed']:
            logger.info(f"Not sending reminder for {appointment.id} - status: {appointment.status}")
            return False
            
        # Get appointment details for template
        context = {
            'patient_name': appointment.patient.get_full_name(),
            'doctor_name': f"Dr. {appointment.provider.last_name}" if appointment.provider else "Your provider",
            'appointment_time': appointment.scheduled_time.strftime('%A, %B %d, %Y at %I:%M %p'),
            'appointment_type': appointment.get_appointment_type_display(),
            'appointment_id': appointment.id,
            'is_video': appointment.appointment_type == 'video_consultation',
            'portal_url': settings.FRONTEND_URL,
        }
        
        # Render email content
        html_content = render_to_string('telemedicine/emails/appointment_reminder.html', context)
        text_content = strip_tags(html_content)
        
        # Create email
        subject = f"Reminder: Your Appointment on {appointment.scheduled_time.strftime('%B %d')}"
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = appointment.patient.email
        
        # Send email
        email = EmailMultiAlternatives(subject, text_content, from_email, [to_email])
        email.attach_alternative(html_content, "text/html")
        email.send()
        
        # Update appointment reminder status
        appointment.reminder_sent = True
        appointment.reminder_sent_time = timezone.now()
        appointment.save(update_fields=['reminder_sent', 'reminder_sent_time'])
        
        logger.info(f"Appointment reminder sent for appointment {appointment.id}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send appointment reminder: {str(e)}")
        raise NotificationException(f"Failed to send appointment reminder: {str(e)}")


def send_appointment_confirmation(appointment):
    """
    Send appointment confirmation to the patient.
    
    Args:
        appointment: Newly created or confirmed appointment
    
    Returns:
        bool: True if notification was sent successfully
    
    Raises:
        NotificationException: If sending fails
    """
    try:
        if not appointment.patient.email:
            logger.warning(f"Cannot send confirmation - no email for patient {appointment.patient.id}")
            return False
            
        # Get appointment details for template
        context = {
            'patient_name': appointment.patient.get_full_name(),
            'doctor_name': f"Dr. {appointment.provider.last_name}" if appointment.provider else "Your provider",
            'appointment_time': appointment.scheduled_time.strftime('%A, %B %d, %Y at %I:%M %p'),
            'appointment_end_time': appointment.end_time.strftime('%I:%M %p'),
            'appointment_type': appointment.get_appointment_type_display(),
            'appointment_id': appointment.id,
            'is_video': appointment.appointment_type == 'video_consultation',
            'portal_url': settings.FRONTEND_URL,
            'reason': appointment.reason
        }
        
        # Render email content
        html_content = render_to_string('telemedicine/emails/appointment_confirmation.html', context)
        text_content = strip_tags(html_content)
        
        # Create email
        subject = f"Appointment Confirmed for {appointment.scheduled_time.strftime('%B %d')}"
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = appointment.patient.email
        
        # Send email
        email = EmailMultiAlternatives(subject, text_content, from_email, [to_email])
        email.attach_alternative(html_content, "text/html")
        email.send()
        
        logger.info(f"Appointment confirmation sent for appointment {appointment.id}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send appointment confirmation: {str(e)}")
        raise NotificationException(f"Failed to send appointment confirmation: {str(e)}")


def send_appointment_cancellation(appointment, reason=None, notify_provider=True):
    """
    Send appointment cancellation notification.
    
    Args:
        appointment: Cancelled appointment
        reason: Reason for cancellation
        notify_provider: Whether to notify the provider as well
    
    Returns:
        bool: True if notification was sent successfully
    
    Raises:
        NotificationException: If sending fails
    """
    try:
        success = False
        
        # Notify patient
        if appointment.patient.email:
            context = {
                'recipient_name': appointment.patient.get_full_name(),
                'doctor_name': f"Dr. {appointment.provider.last_name}" if appointment.provider else "Your provider",
                'appointment_time': appointment.scheduled_time.strftime('%A, %B %d, %Y at %I:%M %p'),
                'appointment_type': appointment.get_appointment_type_display(),
                'reason': reason or "The appointment was cancelled.",
                'portal_url': settings.FRONTEND_URL,
                'is_recipient_patient': True
            }
            
            # Render email content
            html_content = render_to_string('telemedicine/emails/appointment_cancellation.html', context)
            text_content = strip_tags(html_content)
            
            # Create email
            subject = f"Appointment Cancelled: {appointment.scheduled_time.strftime('%B %d')}"
            from_email = settings.DEFAULT_FROM_EMAIL
            to_email = appointment.patient.email
            
            # Send email
            email = EmailMultiAlternatives(subject, text_content, from_email, [to_email])
            email.attach_alternative(html_content, "text/html")
            email.send()
            success = True
            
        # Notify provider if requested
        if notify_provider and appointment.provider.email:
            context = {
                'recipient_name': appointment.provider.get_full_name(),
                'patient_name': appointment.patient.get_full_name(),
                'appointment_time': appointment.scheduled_time.strftime('%A, %B %d, %Y at %I:%M %p'),
                'appointment_type': appointment.get_appointment_type_display(),
                'reason': reason or "The appointment was cancelled.",
                'portal_url': settings.FRONTEND_URL,
                'is_recipient_patient': False
            }
            
            # Render email content
            html_content = render_to_string('telemedicine/emails/appointment_cancellation.html', context)
            text_content = strip_tags(html_content)
            
            # Create email
            subject = f"Appointment Cancelled: {appointment.patient.get_full_name()} on {appointment.scheduled_time.strftime('%B %d')}"
            from_email = settings.DEFAULT_FROM_EMAIL
            to_email = appointment.provider.email
            
            # Send email
            email = EmailMultiAlternatives(subject, text_content, from_email, [to_email])
            email.attach_alternative(html_content, "text/html")
            email.send()
            success = True
            
        if success:
            logger.info(f"Appointment cancellation notification sent for appointment {appointment.id}")
        else:
            logger.warning(f"Could not send cancellation notification - no valid emails found for appointment {appointment.id}")
            
        return success
        
    except Exception as e:
        logger.error(f"Failed to send appointment cancellation notification: {str(e)}")
        raise NotificationException(f"Failed to send appointment cancellation notification: {str(e)}")


def send_consultation_start_notification(consultation):
    """
    Send notification when consultation is starting.
    
    Args:
        consultation: Consultation that is starting
    
    Returns:
        bool: True if notification was sent successfully
    
    Raises:
        NotificationException: If sending fails
    """
    try:
        appointment = consultation.appointment
        success = False
        
        if not appointment:
            logger.warning(f"Cannot send start notification - consultation {consultation.id} has no appointment")
            return False
            
        # Notify patient
        if appointment.patient.email:
            context = {
                'patient_name': appointment.patient.get_full_name(),
                'doctor_name': f"Dr. {appointment.provider.last_name}" if appointment.provider else "Your provider",
                'join_url': consultation.join_url,
                'meeting_id': consultation.meeting_id,
                'password': consultation.password,
                'platform': consultation.get_platform_display(),
                'portal_url': settings.FRONTEND_URL,
            }
            
            # Render email content
            html_content = render_to_string('telemedicine/emails/consultation_starting.html', context)
            text_content = strip_tags(html_content)
            
            # Create email
            subject = "Your Virtual Consultation is Starting Soon"
            from_email = settings.DEFAULT_FROM_EMAIL
            to_email = appointment.patient.email
            
            # Send email
            email = EmailMultiAlternatives(subject, text_content, from_email, [to_email])
            email.attach_alternative(html_content, "text/html")
            email.send()
            success = True
            
        if success:
            logger.info(f"Consultation start notification sent for consultation {consultation.id}")
        else:
            logger.warning(f"Could not send consultation start notification - no valid email for patient")
            
        return success
        
    except Exception as e:
        logger.error(f"Failed to send consultation start notification: {str(e)}")
        raise NotificationException(f"Failed to send consultation start notification: {str(e)}")


def send_prescription_notification(prescription):
    """
    Notify patient about new prescription.
    
    Args:
        prescription: Prescription that was created or updated
    
    Returns:
        bool: True if notification was sent successfully
    
    Raises:
        NotificationException: If sending fails
    """
    try:
        if not prescription.patient.email:
            logger.warning(f"Cannot send prescription notification - no email for patient {prescription.patient.id}")
            return False
            
        # Get prescription details for template
        context = {
            'patient_name': prescription.patient.get_full_name(),
            'doctor_name': f"Dr. {prescription.provider.last_name}" if prescription.provider else "Your provider",
            'medication_name': prescription.medication_name,
            'dosage': prescription.dosage,
            'frequency': prescription.frequency,
            'instructions': prescription.instructions,
            'refills': prescription.refills,
            'portal_url': settings.FRONTEND_URL,
        }
        
        # Render email content
        html_content = render_to_string('telemedicine/emails/new_prescription.html', context)
        text_content = strip_tags(html_content)
        
        # Create email
        subject = f"New Prescription: {prescription.medication_name}"
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = prescription.patient.email
        
        # Send email
        email = EmailMultiAlternatives(subject, text_content, from_email, [to_email])
        email.attach_alternative(html_content, "text/html")
        email.send()
        
        # Update prescription notification status
        prescription.patient_notified = True
        prescription.patient_notification_time = timezone.now()
        prescription.save(update_fields=['patient_notified', 'patient_notification_time'])
        
        logger.info(f"Prescription notification sent for prescription {prescription.id}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send prescription notification: {str(e)}")
        raise NotificationException(f"Failed to send prescription notification: {str(e)}")


def send_sms_reminder(appointment):
    """
    Send SMS reminder for appointment if SMS service is configured.
    
    Args:
        appointment: Appointment to send reminder for
    
    Returns:
        bool: True if SMS was sent successfully
    
    Raises:
        NotificationException: If sending fails
    """
    # This is a placeholder for SMS integration
    # In a real implementation, you would integrate with Twilio, Vonage, or another SMS provider
    
    # Skip if SMS service is not configured
    if not hasattr(settings, 'SMS_ENABLED') or not settings.SMS_ENABLED:
        logger.info("SMS service not enabled - skipping SMS reminder")
        return False
        
    try:
        # Check for phone number
        if not appointment.patient.phone_number:
            logger.warning(f"Cannot send SMS reminder - no phone number for patient {appointment.patient.id}")
            return False
            
        # Check if appointment is suitable for reminder
        if appointment.status not in ['scheduled', 'confirmed']:
            logger.info(f"Not sending SMS reminder for {appointment.id} - status: {appointment.status}")
            return False
            
        # Log the attempt (actual implementation would send the SMS)
        logger.info(f"SMS reminder would be sent to {appointment.patient.phone_number} for appointment {appointment.id}")
        
        # In a real implementation, you would call the SMS service here
        # Example with Twilio:
        # from twilio.rest import Client
        # client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        # message = client.messages.create(
        #     body=f"Reminder: Your appointment with Dr. {appointment.provider.last_name} is on {appointment.scheduled_time.strftime('%B %d at %I:%M %p')}.",
        #     from_=settings.TWILIO_PHONE_NUMBER,
        #     to=appointment.patient.phone_number
        # )
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to send SMS reminder: {str(e)}")
        raise NotificationException(f"Failed to send SMS reminder: {str(e)}")
