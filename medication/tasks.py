from __future__ import absolute_import, unicode_literals
from celery import shared_task
import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Q
from django.contrib.auth import get_user_model
from app.klararety import settings

logger = logging.getLogger(__name__)

User = get_user_model()


@shared_task
def send_due_reminders():
    """
    Send medication reminders that are due.
    Runs every 10 minutes to ensure timely delivery.
    """
    from .models import MedicationReminder
    from .services.reminders import send_reminder
    
    logger.info("Checking for due medication reminders")
    
    now = timezone.now()
    
    # Get due reminders
    due_reminders = MedicationReminder.objects.filter(
        is_active=True,
        scheduled_time__lte=now,
        medication__active=True
    ).select_related('medication', 'patient')
    
    sent_count = 0
    failed_count = 0
    
    for reminder in due_reminders:
        try:
            if send_reminder(reminder):
                sent_count += 1
            else:
                failed_count += 1
        except Exception as e:
            logger.error(f"Error sending reminder {reminder.id}: {str(e)}")
            failed_count += 1
    
    logger.info(f"Sent {sent_count} reminders, {failed_count} failed")
    return f"Sent {sent_count} reminders, {failed_count} failed"

@shared_task 
def check_missed_doses():
    """
    Check for missed medication doses and update intake records.
    """
    from .models import MedicationIntake, MedicationReminder
    
    logger.info("Checking for missed medication doses")
    
    now = timezone.now()
    grace_period = timedelta(hours=2)  # 2-hour grace period
    
    # Find scheduled intakes that are overdue
    overdue_time = now - grace_period
    
    # Update missed doses
    missed_intakes = MedicationIntake.objects.filter(
        scheduled_time__lt=overdue_time,
        status=MedicationIntake.Status.MISSED,
        actual_time__isnull=True
    )
    
    missed_count = 0
    for intake in missed_intakes:
        # For critical rare disease medications, escalate
        if intake.medication.for_rare_condition:
            _escalate_missed_critical_dose(intake)
        missed_count += 1
    
    logger.info(f"Processed {missed_count} missed doses")
    return f"Processed {missed_count} missed doses"

def _escalate_missed_critical_dose(intake):
    """Escalate missed critical doses to providers."""
    from communication.tasks import send_missed_dose_alert
    
    if intake.medication.prescriber:
        send_missed_dose_alert.delay(
            provider_id=intake.medication.prescriber.id,
            patient_id=intake.medication.patient.id,
            medication_id=intake.medication.id,
            missed_time=intake.scheduled_time.isoformat()
        )

@shared_task
def generate_medication_schedules():
    """Generate medication intake schedules for active medications."""
    from .models import Medication, MedicationIntake
    from datetime import date, timedelta
    
    logger.info("Generating medication schedules")
    
    today = date.today()
    tomorrow = today + timedelta(days=1)
    
    # Get active medications
    active_medications = Medication.objects.filter(active=True)
    
    schedules_created = 0
    
    for medication in active_medications:
        # Parse schedule
        schedule = medication.adherence_schedule or {'frequency': 'daily', 'times': ['08:00']}
        times = schedule.get('times', ['08:00'])
        
        for time_str in times:
            # Parse time
            try:
                time_obj = datetime.strptime(time_str, '%H:%M').time()
                scheduled_datetime = timezone.make_aware(datetime.combine(tomorrow, time_obj))
                
                # Create intake record if it doesn't exist
                intake, created = MedicationIntake.objects.get_or_create(
                    medication=medication,
                    scheduled_time=scheduled_datetime,
                    defaults={
                        'status': MedicationIntake.Status.MISSED,
                        'recorded_via': 'system'
                    }
                )
                
                if created:
                    schedules_created += 1
                    
            except ValueError:
                logger.error(f"Invalid time format for medication {medication.id}: {time_str}")
    
    logger.info(f"Created {schedules_created} new medication schedules")
    return f"Created {schedules_created} new medication schedules"

@shared_task
def update_adherence_records():
    """
    Update medication adherence records for all patients.
    
    This task recalculates adherence metrics for all active medications.
    """
    # Import models and services here to avoid circular imports
    from .models import Medication
    from .services.adherence import calculate_adherence
    
    logger.info("Starting adherence record update")
    
    try:
        # Get active medications
        active_medications = Medication.objects.filter(active=True)
        
        # Update adherence for each medication
        updated_count = 0
        for medication in active_medications:
            try:
                calculate_adherence(medication, force_recalculate=True)
                updated_count += 1
            except Exception as med_error:
                logger.error(f"Error updating adherence for medication {medication.id}: {str(med_error)}")
        
        logger.info(f"Updated adherence records for {updated_count} medications")
        return f"Updated adherence records for {updated_count} medications"
    
    except Exception as e:
        logger.error(f"Error updating adherence records: {str(e)}")
        return f"Error updating adherence records: {str(e)}"


@shared_task
def check_all_patient_interactions():
    """
    Check for drug interactions for all patients.
    
    This task checks for drug interactions between medications
    for all patients with active medications.
    """
    # Import models and services here to avoid circular imports
    from .services.interactions import check_all_interactions
    
    logger.info("Starting drug interaction check for all patients")
    
    try:
        # Get all patients
        patients = User.objects.filter(role='patient')
        
        # Check interactions for each patient
        total_interactions = 0
        for patient in patients:
            try:
                interactions = check_all_interactions(patient)
                total_interactions += len(interactions)
            except Exception as patient_error:
                logger.error(f"Error checking interactions for patient {patient.id}: {str(patient_error)}")
        
        logger.info(f"Found {total_interactions} drug interactions")
        return f"Found {total_interactions} drug interactions"
    
    except Exception as e:
        logger.error(f"Error checking drug interactions: {str(e)}")
        return f"Error checking drug interactions: {str(e)}"


@shared_task
def check_expiring_prescriptions():
    """
    Check for prescriptions that are about to expire.
    
    This task identifies prescriptions that will expire within the next
    week and sends reminders to patients to get them refilled.
    """
    # Import models here to avoid circular imports
    from .models import Prescription, MedicationReminder
    from django.core.mail import send_mail
    
    logger.info("Starting expiring prescriptions check")
    
    try:
        # Get current date
        today = timezone.now().date()
        
        # Define expiration warning period (e.g., 7 days)
        warning_days = 7
        warning_date = today + timedelta(days=warning_days)
        
        # Find active prescriptions expiring within the warning period
        expiring_prescriptions = Prescription.objects.filter(
            status='active',
            expiration_date__lte=warning_date,
            expiration_date__gt=today
        )
        
        # Create reminders and send notifications
        reminder_count = 0
        for prescription in expiring_prescriptions:
            try:
                # Create a refill reminder if one doesn't exist
                reminder, created = MedicationReminder.objects.get_or_create(
                    patient=prescription.patient,
                    reminder_type='refill',
                    defaults={
                        'medication': prescription.medication,
                        'message': f"Your prescription for {prescription.medication_name} will expire in {(prescription.expiration_date - today).days} days. Please get it refilled.",
                        'frequency': 'once',
                        'scheduled_time': timezone.now(),  # Send immediately
                        'is_active': True
                    }
                )
                
                if created:
                    reminder_count += 1
                    
                    # Send email notification
                    if prescription.patient.email:
                        days_remaining = (prescription.expiration_date - today).days
                        send_mail(
                            subject=f"Prescription Expiring Soon: {prescription.medication_name}",
                            message=f"""
                            Dear {prescription.patient.get_full_name()},
                            
                            Your prescription for {prescription.medication_name} will expire in {days_remaining} days.
                            
                            Please contact your healthcare provider to get a new prescription or a refill.
                            
                            Prescription details:
                            - Medication: {prescription.medication_name}
                            - Dosage: {prescription.dosage}
                            - Prescribed by: Dr. {prescription.prescriber.last_name if prescription.prescriber else 'Unknown'}
                            - Expiration date: {prescription.expiration_date}
                            
                            Thank you,
                            Klararety Health Platform
                            """,
                            from_email=settings.DEFAULT_FROM_EMAIL,
                            recipient_list=[prescription.patient.email],
                            fail_silently=True
                        )
            except Exception as rx_error:
                logger.error(f"Error processing expiring prescription {prescription.id}: {str(rx_error)}")
        
        logger.info(f"Created {reminder_count} reminders for expiring prescriptions")
        return f"Created {reminder_count} reminders for expiring prescriptions"
    
    except Exception as e:
        logger.error(f"Error checking expiring prescriptions: {str(e)}")
        return f"Error checking expiring prescriptions: {str(e)}"

