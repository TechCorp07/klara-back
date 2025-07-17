import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.urls import reverse

logger = logging.getLogger(__name__)

def generate_reminders(medication):
    """
    Generate reminders for a medication based on its schedule.
    
    Args:
        medication: Medication object to generate reminders for
        
    Returns:
        List of created MedicationReminder objects
    """
    # Import models here to avoid circular imports
    from ..models import MedicationReminder
    
    # Check if medication is active
    if not medication.active:
        return []
    
    reminders = []
    
    # Generate dose reminders based on frequency
    if medication.frequency_unit == 'daily':
        # Daily medication, create reminders for each specific time
        specific_times = medication.specific_times or []
        
        if not specific_times and medication.times_per_frequency > 0:
            # No specific times set, create evenly spaced reminders
            # Start at 8 AM by default
            start_hour = 8
            hours_between = 24 // medication.times_per_frequency
            
            for i in range(medication.times_per_frequency):
                hour = (start_hour + i * hours_between) % 24
                specific_times.append(f"{hour:02d}:00")
        
        # Create reminders for each time
        for time_str in specific_times:
            try:
                # Parse time string
                hour, minute = map(int, time_str.split(':'))
                
                # Create reminder
                now = timezone.now()
                scheduled_time = timezone.make_aware(
                    datetime.combine(now.date(), datetime.min.time()) + 
                    timedelta(hours=hour, minutes=minute)
                )
                
                # If today's time has passed, schedule for tomorrow
                if scheduled_time < now:
                    scheduled_time += timedelta(days=1)
                
                reminder, created = MedicationReminder.objects.get_or_create(
                    medication=medication,
                    patient=medication.patient,
                    reminder_type='dose',
                    frequency='daily',
                    scheduled_time=scheduled_time,
                    defaults={
                        'message': f"Time to take {medication.name} {medication.dosage}",
                        'is_active': True,
                        'created_by': medication.created_by
                    }
                )
                
                if created:
                    reminders.append(reminder)
                
            except ValueError:
                logger.error(f"Invalid time format: {time_str}")
    
    elif medication.frequency_unit == 'weekly':
        # Weekly medication, create reminders for specific days
        days = medication.specific_times or [0]  # Default to Monday (0)
        
        for day in days:
            # Calculate next occurrence of this day
            now = timezone.now()
            current_day = now.weekday()
            days_ahead = (day - current_day) % 7
            
            # If it's today but time has passed, schedule for next week
            if days_ahead == 0 and now.hour >= 8:  # Assuming reminder at 8 AM
                days_ahead = 7
            
            scheduled_date = now.date() + timedelta(days=days_ahead)
            scheduled_time = timezone.make_aware(
                datetime.combine(scheduled_date, datetime.min.time()) + 
                timedelta(hours=8)  # Default to 8 AM
            )
            
            reminder, created = MedicationReminder.objects.get_or_create(
                medication=medication,
                patient=medication.patient,
                reminder_type='dose',
                frequency='weekly',
                scheduled_time=scheduled_time,
                defaults={
                    'message': f"Time to take your weekly {medication.name} {medication.dosage}",
                    'is_active': True,
                    'created_by': medication.created_by
                }
            )
            
            if created:
                reminders.append(reminder)
    
    elif medication.frequency_unit == 'monthly':
        # Monthly medication, create reminder for specific day of month
        day = medication.specific_times[0] if medication.specific_times else 1  # Default to 1st day
        
        # Calculate next occurrence of this day
        now = timezone.now()
        current_day = now.day
        
        if day < current_day or (day == current_day and now.hour >= 8):
            # If this month's day has passed, schedule for next month
            next_month = now.replace(day=1) + timedelta(days=32)  # Go to next month
            next_month = next_month.replace(day=min(day, [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][next_month.month-1]))
            scheduled_date = next_month.date()
        else:
            # Schedule for this month
            scheduled_date = now.replace(day=day).date()
        
        scheduled_time = timezone.make_aware(
            datetime.combine(scheduled_date, datetime.min.time()) + 
            timedelta(hours=8)  # Default to 8 AM
        )
        
        reminder, created = MedicationReminder.objects.get_or_create(
            medication=medication,
            patient=medication.patient,
            reminder_type='dose',
            frequency='monthly',
            scheduled_time=scheduled_time,
            defaults={
                'message': f"Time to take your monthly {medication.name} {medication.dosage}",
                'is_active': True,
                'created_by': medication.created_by
            }
        )
        
        if created:
            reminders.append(reminder)
    
    # Generate refill reminders if applicable
    if medication.prescription_required and medication.refills_remaining <= 1:
        # Create a refill reminder if it doesn't exist
        refill_reminder, created = MedicationReminder.objects.get_or_create(
            medication=medication,
            patient=medication.patient,
            reminder_type='refill',
            defaults={
                'message': f"Time to refill your prescription for {medication.name}",
                'frequency': 'once',
                'scheduled_time': timezone.now() + timedelta(days=7),  # Default to 1 week in advance
                'is_active': True,
                'created_by': medication.created_by
            }
        )
        
        if created:
            reminders.append(refill_reminder)
    
    return reminders


def send_reminder(reminder):
    """
    Send a medication reminder to the patient.
    
    Args:
        reminder: MedicationReminder object to send
        
    Returns:
        Boolean indicating success
    """
    if not reminder.is_active:
        return False
    
    success = False
    
    # Send email reminder if enabled
    if reminder.send_email and reminder.patient.email:
        success = send_email_reminder(reminder) or success
    
    # Send push notification if enabled
    if reminder.send_push:
        success = send_push_reminder(reminder) or success
    
    # Send SMS reminder if enabled
    if reminder.send_sms and hasattr(reminder.patient, 'phone_number') and reminder.patient.phone_number:
        success = send_sms_reminder(reminder) or success
    
    # Update last sent timestamp if any method was successful
    if success:
        reminder.last_sent = timezone.now()
        reminder.save(update_fields=['last_sent'])
    
    return success


def send_email_reminder(reminder):
    """
    Send an email reminder.
    
    Args:
        reminder: MedicationReminder object to send
        
    Returns:
        Boolean indicating success
    """
    try:
        # Create context for email template
        medication = reminder.medication
        patient = reminder.patient
        
        context = {
            'patient_name': patient.get_full_name() or patient.username,
            'medication_name': medication.name,
            'dosage': medication.dosage,
            'reminder_message': reminder.message,
            'reminder_type': reminder.get_reminder_type_display(),
            'app_link': f"{settings.FRONTEND_URL}/medications/{medication.id}"
        }
        
        # Choose template based on reminder type
        if reminder.reminder_type == 'dose':
            template = 'emails/dose_reminder.html'
            subject = f"Medication Reminder: Time to take {medication.name}"
        elif reminder.reminder_type == 'refill':
            template = 'emails/refill_reminder.html'
            subject = f"Prescription Refill Reminder: {medication.name}"
        else:
            template = 'emails/generic_reminder.html'
            subject = f"Medication Reminder: {medication.name}"
        
        # Render email content
        html_content = render_to_string(template, context)
        
        # Send email
        send_mail(
            subject=subject,
            message=reminder.message,  # Plain text version
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[patient.email],
            html_message=html_content,
            fail_silently=False
        )
        
        logger.info(f"Email reminder sent to {patient.email}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending email reminder: {str(e)}")
        return False


def send_push_reminder(reminder):
    """
    Send a push notification reminder.
    
    Args:
        reminder: MedicationReminder object to send
        
    Returns:
        Boolean indicating success
    """
    try:
        # This is a placeholder - in a real application, you would integrate
        # with a push notification service like Firebase Cloud Messaging (FCM)
        
        logger.info(f"Push notification would be sent to {reminder.patient.username}")
        
        # For now, just log and return success (simulate push notification)
        return True
        
    except Exception as e:
        logger.error(f"Error sending push reminder: {str(e)}")
        return False


def send_sms_reminder(reminder):
    """
    Send an SMS reminder.
    
    Args:
        reminder: MedicationReminder object to send
        
    Returns:
        Boolean indicating success
    """
    try:
        # This is a placeholder - in a real application, you would integrate
        # with an SMS service like Twilio or Vonage
        
        patient = reminder.patient
        
        if not hasattr(patient, 'phone_number') or not patient.phone_number:
            logger.warning(f"Cannot send SMS - no phone number for {patient.username}")
            return False
        
        logger.info(f"SMS would be sent to {patient.phone_number}")
        
        # For now, just log and return success (simulate SMS)
        return True
        
    except Exception as e:
        logger.error(f"Error sending SMS reminder: {str(e)}")
        return False


def check_due_reminders():
    """
    Check for reminders that are due to be sent.
    
    This function should be called by a scheduled task.
    
    Returns:
        Number of reminders sent
    """
    # Import models here to avoid circular imports
    from ..models import MedicationReminder
    
    # Get active reminders
    active_reminders = MedicationReminder.objects.filter(is_active=True)
    
    sent_count = 0
    
    # Check each reminder
    for reminder in active_reminders:
        if reminder.is_due():
            success = send_reminder(reminder)
            if success:
                sent_count += 1
                
                # Update one-time reminders
                if reminder.frequency == 'once':
                    reminder.is_active = False
                    reminder.save(update_fields=['is_active'])
    
    return sent_count
