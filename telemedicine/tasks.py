from __future__ import absolute_import, unicode_literals
from celery import shared_task
import logging
from datetime import timedelta
from django.utils import timezone
from django.db.models import Q
from .services.rare_disease_consultation import RareDiseaseConsultationService
from .services.notifications_service import telemedicine_notifications
from healthcare.models import Medication

from .models import (
    Appointment, Consultation, Prescription,
    ProviderAvailability, WaitingRoomPatient
)
from .services import notifications_service

logger = logging.getLogger(__name__)


@shared_task
def send_appointment_reminders():
    """Enhanced appointment reminders with smartwatch support."""
    logger.info("Starting appointment reminder task")
    
    now = timezone.now()
    reminder_window_end = now + timedelta(hours=24)
    
    upcoming_appointments = Appointment.objects.filter(
        scheduled_time__gt=now,
        scheduled_time__lte=reminder_window_end,
        reminder_sent=False,
        status__in=['scheduled', 'confirmed']
    )
    
    success_count = 0
    failure_count = 0
    
    for appointment in upcoming_appointments:
        try:
            # Use your existing telemedicine notification service
            sent = telemedicine_notifications.send_appointment_reminder(appointment)
            
            # Also send smartwatch notification if patient has wearable integration
            try:
                if hasattr(appointment.patient, 'patient_profile') and \
                   appointment.patient.patient_profile.smartwatch_integration_active:
                    
                    from wearables.services.notification_service import WearableNotificationService
                    
                    WearableNotificationService.send_appointment_reminder(
                        user=appointment.patient,
                        title=f"Appointment Reminder",
                        message=f"You have an appointment with {appointment.provider.get_full_name()} in {(appointment.scheduled_time - now).total_seconds() // 3600:.0f} hours",
                        appointment_id=appointment.id,
                        scheduled_time=appointment.scheduled_time.isoformat()
                    )
                    
            except Exception as smartwatch_error:
                logger.warning(f"Smartwatch reminder failed for appointment {appointment.id}: {str(smartwatch_error)}")
            
            if sent:
                success_count += 1
            else:
                failure_count += 1
                
        except Exception as e:
            logger.error(f"Error sending reminder for appointment {appointment.id}: {str(e)}")
            failure_count += 1
    
    logger.info(f"Appointment reminder task completed: {success_count} sent, {failure_count} failed")
    return f"{success_count} reminders sent, {failure_count} failed"


@shared_task
def check_missed_appointments():
    """
    Task to mark appointments as no-shows if they were missed.
    
    Marks appointments as no-shows if:
    - The appointment end time has passed
    - The appointment was scheduled or confirmed
    - No consultations were started for the appointment
    """
    logger.info("Starting missed appointment check task")
    
    # Get current time
    now = timezone.now()
    
    # Find appointments that have ended but were not cancelled or completed
    missed_appointments = Appointment.objects.filter(
        end_time__lt=now,
        status__in=['scheduled', 'confirmed']
    )
    
    no_show_count = 0
    
    for appointment in missed_appointments:
        # Check if any consultations were started
        has_consultations = appointment.consultations.filter(
            status__in=['in_progress', 'completed']
        ).exists()
        
        if not has_consultations:
            # Mark as no-show
            appointment.status = Appointment.Status.NO_SHOW
            appointment.notes += f"\n\nMarked as no-show on {now.strftime('%Y-%m-%d %H:%M')}."
            appointment.save(update_fields=['status', 'notes'])
            
            # Cancel any pending consultations
            appointment.consultations.filter(
                status__in=['scheduled', 'ready']
            ).update(status='cancelled')
            
            no_show_count += 1
    
    logger.info(f"Missed appointment check completed: {no_show_count} no-shows marked")
    return f"{no_show_count} appointments marked as no-shows"


@shared_task
def check_prescription_expiration():
    """
    Task to mark prescriptions as expired.
    
    Marks prescriptions as expired if:
    - The expiration date has passed
    - The prescription was active or pending
    """
    logger.info("Starting prescription expiration check task")
    
    # Get current date
    today = timezone.now().date()
    
    # Find prescriptions that have expired
    expired_prescriptions = Prescription.objects.filter(
        expiration_date__lt=today,
        status__in=['active', 'pending']
    )
    
    expired_count = 0
    
    for prescription in expired_prescriptions:
        # Mark as expired
        prescription.status = Prescription.Status.EXPIRED
        prescription.save(update_fields=['status'])
        expired_count += 1
    
    logger.info(f"Prescription expiration check completed: {expired_count} prescriptions marked as expired")
    return f"{expired_count} prescriptions marked as expired"


@shared_task
def generate_provider_availability():
    """
    Task to generate recurring provider availability.
    
    Examines availability blocks with recurrence patterns and generates
    new blocks based on those patterns for the upcoming period.
    """
    logger.info("Starting provider availability generation task")
    
    # Get current time
    now = timezone.now()
    
    # Look ahead period (e.g., 30 days)
    look_ahead_end = now + timedelta(days=30)
    
    # Find availability blocks with recurrence patterns
    recurring_blocks = ProviderAvailability.objects.filter(
        recurrence_pattern__isnull=False,
        recurrence_pattern__gt=''
    )
    
    blocks_generated = 0
    
    for block in recurring_blocks:
        try:
            # In a real implementation, this would use a library like dateutil.rrule
            # to generate instances based on the recurrence pattern
            # For simplicity, this is just a placeholder
            
            # Example logic for weekly recurrence (assuming format like "FREQ=WEEKLY")
            if "FREQ=WEEKLY" in block.recurrence_pattern:
                # Get the most recent occurrence of this block
                last_occurrence = ProviderAvailability.objects.filter(
                    provider=block.provider,
                    start_time__time=block.start_time.time(),
                    end_time__time=block.end_time.time(),
                ).order_by('-start_time').first()
                
                if last_occurrence:
                    last_date = last_occurrence.start_time.date()
                    # Generate for the next 4 weeks
                    for week in range(1, 5):
                        next_date = last_date + timedelta(days=7 * week)
                        next_start = timezone.make_aware(
                            timezone.datetime.combine(next_date, block.start_time.time())
                        )
                        next_end = timezone.make_aware(
                            timezone.datetime.combine(next_date, block.end_time.time())
                        )
                        
                        # Skip if already in the past
                        if next_end < now:
                            continue
                        
                        # Skip if beyond look ahead period
                        if next_start > look_ahead_end:
                            continue
                        
                        # Skip if already exists
                        if ProviderAvailability.objects.filter(
                            provider=block.provider,
                            start_time=next_start,
                            end_time=next_end
                        ).exists():
                            continue
                        
                        # Create new availability block
                        new_block = ProviderAvailability.objects.create(
                            provider=block.provider,
                            start_time=next_start,
                            end_time=next_end,
                            is_available=block.is_available,
                            appointment_types=block.appointment_types,
                            slot_duration_minutes=block.slot_duration_minutes,
                            max_appointments=block.max_appointments,
                            recurrence_pattern=block.recurrence_pattern
                        )
                        
                        blocks_generated += 1
        
        except Exception as e:
            logger.error(f"Error generating availability for block {block.id}: {str(e)}")
    
    logger.info(f"Provider availability generation completed: {blocks_generated} blocks generated")
    return f"{blocks_generated} availability blocks generated"


@shared_task
def clean_waiting_room():
    """
    Task to clean up waiting room entries.
    
    Removes patients from waiting rooms if:
    - The patient's appointment has ended
    - The patient's appointment was cancelled
    - The patient has been waiting for an excessive amount of time
    """
    logger.info("Starting waiting room cleanup task")
    
    # Get current time
    now = timezone.now()
    
    # Find waiting room entries to clean up
    waiting_entries = WaitingRoomPatient.objects.filter(
        status='waiting'
    )
    
    removed_count = 0
    
    for entry in waiting_entries:
        try:
            appointment = entry.appointment
            
            # Check if appointment exists and has valid status
            if not appointment or appointment.status in ['cancelled', 'completed', 'no_show']:
                entry.status = WaitingRoomPatient.Status.CANCELLED
                entry.save(update_fields=['status'])
                removed_count += 1
                continue
            
            # Check if appointment time has passed
            if appointment.end_time < now:
                entry.status = WaitingRoomPatient.Status.COMPLETED
                entry.save(update_fields=['status'])
                removed_count += 1
                continue
            
            # Check for excessive wait time (e.g., > 1 hour)
            wait_duration = now - entry.checked_in_time
            if wait_duration.total_seconds() > 3600:  # 1 hour
                entry.status = WaitingRoomPatient.Status.CANCELLED
                entry.save(update_fields=['status'])
                removed_count += 1
                continue
                
        except Exception as e:
            logger.error(f"Error cleaning up waiting room entry {entry.id}: {str(e)}")
    
    logger.info(f"Waiting room cleanup completed: {removed_count} entries cleaned up")
    return f"{removed_count} waiting room entries cleaned up"


@shared_task
def end_abandoned_consultations():
    """
    Task to end consultations that were abandoned.
    
    Ends consultations if:
    - The consultation was in progress
    - The appointment end time has passed
    - The consultation was not manually ended
    """
    logger.info("Starting abandoned consultation check task")
    
    # Get current time
    now = timezone.now()
    
    # Find consultations that are still in progress but should have ended
    abandoned_consultations = Consultation.objects.filter(
        status='in_progress',
        appointment__end_time__lt=now
    )
    
    ended_count = 0
    
    for consultation in abandoned_consultations:
        try:
            # Mark consultation as completed
            consultation.status = Consultation.Status.COMPLETED
            consultation.end_time = now
            
            # Calculate duration
            if consultation.start_time:
                duration = (now - consultation.start_time).total_seconds() / 60
                consultation.duration = int(duration)
            
            consultation.save(update_fields=['status', 'end_time', 'duration'])
            
            # Update appointment status
            appointment = consultation.appointment
            if appointment and appointment.status == Appointment.Status.IN_PROGRESS:
                appointment.status = Appointment.Status.COMPLETED
                appointment.save(update_fields=['status'])
            
            ended_count += 1
                
        except Exception as e:
            logger.error(f"Error ending abandoned consultation {consultation.id}: {str(e)}")
    
    logger.info(f"Abandoned consultation check completed: {ended_count} consultations ended")
    return f"{ended_count} abandoned consultations ended"


@shared_task
def send_consultation_preparation_reminder(appointment_id, is_final_reminder=False):
    """
    Send consultation preparation reminder for rare disease patients.
    Includes vitals collection, medication adherence check, and symptom updates.
    """
    try:
        appointment = Appointment.objects.get(id=appointment_id)
        
        # Check if this is a rare disease consultation
        if not appointment.medical_record or not appointment.medical_record.has_rare_condition:
            return "Not a rare disease consultation"
        
        # Prepare reminder data
        from .services.rare_disease_consultation import RareDiseaseConsultationService
        
        preparation_data = RareDiseaseConsultationService.prepare_rare_disease_consultation(appointment)
        
        # Create preparation checklist for patient
        patient_checklist = []
        
        if preparation_data.get('medication_adherence', {}).get('concerning_medications'):
            patient_checklist.append("Review your medication adherence with any missed doses")
        
        if preparation_data.get('symptom_tracking', {}).get('active_symptoms'):
            patient_checklist.append("Update your symptom diary with any new or changed symptoms")
        
        patient_checklist.extend([
            "Take your vital signs if you have a home monitoring device",
            "Prepare a list of questions for your provider",
            "Ensure your device is charged and internet connection is stable (for video calls)",
            "Have your current medications list ready"
        ])
        
        reminder_data = {
            'appointment_id': str(appointment.id),
            'provider_name': appointment.provider.get_full_name(),
            'scheduled_time': appointment.scheduled_time.isoformat(),
            'is_final_reminder': is_final_reminder,
            'preparation_checklist': patient_checklist,
            'estimated_duration': appointment.duration_minutes
        }
        
        # Send to patient
        patient_success = telemedicine_notifications.notification_service.send_email(
            recipient=appointment.patient.email,
            subject=f"{'Final ' if is_final_reminder else ''}Preparation Reminder: Upcoming Consultation",
            template='consultation_preparation_reminder',
            context=reminder_data
        )
        
        # Send to caregivers
        caregiver_success = telemedicine_notifications._send_caregiver_notifications(
            appointment.patient, 
            reminder_data, 
            'preparation_reminder'
        )
        
        return f"Preparation reminder sent - Patient: {patient_success}, Caregivers: {caregiver_success}"
        
    except Appointment.DoesNotExist:
        return f"Appointment {appointment_id} not found"
    except Exception as e:
        logger.error(f"Error sending consultation preparation reminder: {str(e)}")
        return f"Error: {str(e)}"


@shared_task
def sync_consultation_with_medication_reminders(consultation_id):
    """
    Sync consultation schedule with medication reminder system.
    Ensures medication reminders don't conflict with consultation times.
    """
    try:
        consultation = Consultation.objects.get(id=consultation_id)
        
        if consultation.status != Consultation.Status.IN_PROGRESS:
            return "Consultation not in progress"
        
        # Get patient's active medications
        active_medications = Medication.objects.filter(
            patient=consultation.patient,
            active=True
        )
        
        # Check for medication reminders during consultation time
        consultation_start = consultation.start_time or consultation.appointment.scheduled_time
        consultation_end = consultation_start + timedelta(minutes=consultation.duration or 30)
        
        # Import medication reminder models
        from medication.models import MedicationReminder
        
        # Get reminders that would fire during consultation
        conflicting_reminders = MedicationReminder.objects.filter(
            patient=consultation.patient,
            scheduled_time__gte=consultation_start,
            scheduled_time__lte=consultation_end,
            is_active=True
        )
        
        notifications_sent = 0
        
        for reminder in conflicting_reminders:

            medication_info = {
                'name': reminder.medication.name,
                'dosage': reminder.medication.dosage,
                'scheduled_time': reminder.scheduled_time.isoformat(),
                'for_rare_condition': reminder.medication.for_rare_condition
            }
            
            if telemedicine_notifications.send_medication_reminder_during_consultation(
                consultation, medication_info
            ):
                notifications_sent += 1
        
        return f"Processed {conflicting_reminders.count()} conflicting reminders, sent {notifications_sent} notifications"
        
    except Consultation.DoesNotExist:
        return f"Consultation {consultation_id} not found"
    except Exception as e:
        logger.error(f"Error syncing consultation with medication reminders: {str(e)}")
        return f"Error: {str(e)}"


def send_appointment_reminders_sync():
    """Synchronous version for testing without Celery."""
    logger.info("Starting appointment reminder task (sync)")
    
    now = timezone.now()
    reminder_window_end = now + timedelta(hours=24)
    
    upcoming_appointments = Appointment.objects.filter(
        scheduled_time__gt=now,
        scheduled_time__lte=reminder_window_end,
        reminder_sent=False,
        status__in=['scheduled', 'confirmed']
    )
    
    success_count = 0
    failure_count = 0
    
    for appointment in upcoming_appointments:
        try:
            # Use your existing telemedicine notification service
            sent = telemedicine_notifications.send_appointment_reminder(appointment)
            
            if sent:
                success_count += 1
            else:
                failure_count += 1
                
        except Exception as e:
            logger.error(f"Error sending reminder for appointment {appointment.id}: {str(e)}")
            failure_count += 1
    
    logger.info(f"Appointment reminder task completed: {success_count} sent, {failure_count} failed")
    return f"{success_count} reminders sent, {failure_count} failed"
