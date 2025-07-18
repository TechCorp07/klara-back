# medication/services/reminders.py
import logging
from django.utils import timezone
from django.conf import settings
from datetime import datetime, timedelta
from typing import List, Dict, Any

from ..models import Medication, MedicationReminder
from communication.services import NotificationService

logger = logging.getLogger(__name__)

def generate_reminders(medication: Medication) -> List[MedicationReminder]:
    """
    Generate medication reminders based on patient preferences and medication schedule.
    Critical for rare disease patients who cannot miss doses.
    """
    if not medication.active or not medication.patient.patient_profile.medication_reminder_enabled:
        return []
    
    patient_profile = medication.patient.patient_profile
    reminders = []
    
    # Parse medication schedule from adherence_schedule
    schedule = medication.adherence_schedule or {}
    
    # Default to daily if no specific schedule
    if not schedule:
        schedule = {'frequency': 'daily', 'times': ['08:00']}
    
    # Create reminders based on patient preferences
    frequency = schedule.get('frequency', 'daily')
    times = schedule.get('times', ['08:00'])
    
    for time_str in times:
        reminder = MedicationReminder.objects.create(
            medication=medication,
            patient=medication.patient,
            reminder_type='dose',
            message=f"Time to take your {medication.name} ({medication.dosage})",
            frequency=frequency,
            scheduled_time=_parse_time_string(time_str),
            
            # Use patient notification preferences
            send_email='email' in patient_profile.medication_reminder_methods,
            send_push='push' in patient_profile.medication_reminder_methods,
            send_sms='sms' in patient_profile.medication_reminder_methods,
            send_smartwatch='smartwatch' in patient_profile.medication_reminder_methods,
            
            # Apply advance timing
            advance_minutes=_get_advance_minutes(patient_profile.medication_reminder_frequency),
            
            created_by=medication.prescriber or medication.created_by
        )
        
        reminders.append(reminder)
        
        # For rare disease medications, create additional safety reminder
        if medication.for_rare_condition:
            safety_reminder = MedicationReminder.objects.create(
                medication=medication,
                patient=medication.patient,
                reminder_type='safety',
                message=f"Critical: Don't miss your {medication.name}. Contact your doctor if you experience any side effects.",
                frequency=frequency,
                scheduled_time=_parse_time_string(time_str) + timedelta(hours=1),
                send_email=True,  # Always send safety reminders via email
                send_push=True,
                is_critical=True,
                created_by=medication.prescriber or medication.created_by
            )
            reminders.append(safety_reminder)
    
    logger.info(f"Generated {len(reminders)} reminders for {medication.name}")
    return reminders

def send_reminder(reminder: MedicationReminder) -> bool:
    """
    Send a medication reminder through configured channels.
    """
    try:
        notification_service = NotificationService()
        
        # Prepare message data
        message_data = {
            'medication_name': reminder.medication.name,
            'dosage': reminder.medication.dosage,
            'patient_name': reminder.patient.get_full_name(),
            'reminder_time': reminder.scheduled_time.strftime('%I:%M %p'),
            'is_critical': reminder.is_critical,
            'rare_condition': reminder.medication.for_rare_condition
        }
        
        success = True
        
        # Send email reminder
        if reminder.send_email:
            email_sent = notification_service.send_medication_reminder_email(
                recipient=reminder.patient,
                medication=reminder.medication,
                message_data=message_data
            )
            success = success and email_sent
        
        # Send push notification
        if reminder.send_push:
            push_sent = notification_service.send_push_notification(
                user=reminder.patient,
                title=f"Medication Reminder: {reminder.medication.name}",
                message=reminder.message,
                data={'medication_id': reminder.medication.id, 'type': 'medication_reminder'}
            )
            success = success and push_sent
        
        # Send SMS
        if reminder.send_sms:
            sms_sent = notification_service.send_sms(
                phone_number=reminder.patient.phone_number,
                message=reminder.message
            )
            success = success and sms_sent
        
        # Send smartwatch notification
        if reminder.send_smartwatch and reminder.patient.patient_profile.smartwatch_integration_active:
            smartwatch_sent = _send_smartwatch_reminder(reminder)
            success = success and smartwatch_sent
        
        # Update reminder tracking
        if success:
            reminder.last_sent = timezone.now()
            reminder.times_sent += 1
            reminder.save(update_fields=['last_sent', 'times_sent'])
        
        return success
        
    except Exception as e:
        logger.error(f"Failed to send reminder {reminder.id}: {str(e)}")
        return False

def _send_smartwatch_reminder(reminder: MedicationReminder) -> bool:
    """Send reminder to patient's smartwatch."""
    try:
        # This would integrate with wearables module
        from wearables.services import send_watch_notification
        
        return send_watch_notification(
            device_id=reminder.patient.patient_profile.smartwatch_device_id,
            title="Medication Time",
            message=reminder.message,
            medication_id=reminder.medication.id
        )
    except ImportError:
        logger.warning("Wearables module not available for smartwatch notifications")
        return False
    except Exception as e:
        logger.error(f"Failed to send smartwatch reminder: {str(e)}")
        return False

def _parse_time_string(time_str: str) -> datetime:
    """Parse time string into datetime object for today."""
    try:
        time_obj = datetime.strptime(time_str, '%H:%M').time()
        today = timezone.now().date()
        return timezone.make_aware(datetime.combine(today, time_obj))
    except ValueError:
        # Default to 8 AM if parsing fails
        return timezone.make_aware(datetime.combine(timezone.now().date(), datetime.strptime('08:00', '%H:%M').time()))

def _get_advance_minutes(frequency: str) -> int:
    """Convert frequency to advance minutes."""
    mapping = {
        'immediate': 0,
        '15min': 15,
        '30min': 30,
        '1hour': 60
    }
    return mapping.get(frequency, 0)