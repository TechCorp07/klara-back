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
    
    This task checks for medication reminders that are due to be sent
    and sends them via the appropriate channels (email, push, SMS).
    """
    # Import here to avoid circular imports
    from .services.reminders import check_due_reminders
    
    logger.info("Starting medication reminder check")
    
    try:
        # Send reminders
        sent_count = check_due_reminders()
        logger.info(f"Sent {sent_count} medication reminders")
        return f"Sent {sent_count} medication reminders"
    
    except Exception as e:
        logger.error(f"Error sending medication reminders: {str(e)}")
        return f"Error sending medication reminders: {str(e)}"


@shared_task
def check_missed_doses():
    """
    Check for missed medication doses.
    
    This task checks for scheduled medication intakes that haven't been 
    marked as taken or skipped and updates them as missed.
    """
    # Import models here to avoid circular imports
    from .models import MedicationIntake
    
    logger.info("Starting missed doses check")
    
    try:
        # Get current time
        now = timezone.now()
        
        # Define the grace period (e.g., 1 hour after scheduled time)
        grace_period = timedelta(hours=1)
        
        # Find intakes that are past due and not taken or skipped
        missed_intakes = MedicationIntake.objects.filter(
            Q(status='missed') | Q(status='rescheduled'),
            scheduled_time__lt=now - grace_period
        )
        
        # Update them as missed
        missed_count = missed_intakes.update(status='missed')
        
        logger.info(f"Marked {missed_count} doses as missed")
        return f"Marked {missed_count} doses as missed"
    
    except Exception as e:
        logger.error(f"Error checking missed doses: {str(e)}")
        return f"Error checking missed doses: {str(e)}"


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


@shared_task
def generate_medication_schedules():
    """
    Generate medication intake schedules for active medications.
    
    This task creates scheduled intake events for medications based on
    their frequencies and specific times.
    """
    # Import models here to avoid circular imports
    from .models import Medication, MedicationIntake
    
    logger.info("Starting medication schedule generation")
    
    try:
        # Get active medications
        active_medications = Medication.objects.filter(active=True)
        
        # Track how many schedules we create
        created_count = 0
        
        # Current time and date
        now = timezone.now()
        today = now.date()
        
        # Look ahead period (e.g., 7 days)
        look_ahead_days = 7
        end_date = today + timedelta(days=look_ahead_days)
        
        for medication in active_medications:
            try:
                # Skip medications with end dates in the past
                if medication.end_date and medication.end_date < today and not medication.ongoing:
                    continue
                
                # Get existing intakes in the look-ahead period
                existing_intakes = MedicationIntake.objects.filter(
                    medication=medication,
                    scheduled_time__date__gte=today,
                    scheduled_time__date__lte=end_date
                )
                
                # Skip if we already have scheduled intakes for this period
                if existing_intakes.exists():
                    continue
                
                # Generate intake schedule based on frequency
                if medication.frequency_unit == 'daily':
                    # Daily medication
                    specific_times = medication.specific_times or []
                    
                    if not specific_times and medication.times_per_frequency > 0:
                        # No specific times set, create evenly spaced intakes
                        # Start at 8 AM by default
                        start_hour = 8
                        hours_between = 24 // medication.times_per_frequency
                        
                        for i in range(medication.times_per_frequency):
                            hour = (start_hour + i * hours_between) % 24
                            specific_times.append(f"{hour:02d}:00")
                    
                    # Create intakes for each day and time
                    for day in range(look_ahead_days):
                        intake_date = today + timedelta(days=day)
                        
                        # Skip if medication ends before this date
                        if medication.end_date and medication.end_date < intake_date and not medication.ongoing:
                            continue
                        
                        for time_str in specific_times:
                            try:
                                # Parse time string
                                hour, minute = map(int, time_str.split(':'))
                                
                                # Create scheduled time
                                scheduled_time = timezone.make_aware(
                                    datetime.combine(intake_date, datetime.min.time()) + 
                                    timedelta(hours=hour, minutes=minute)
                                )
                                
                                # Skip times in the past
                                if scheduled_time < now:
                                    continue
                                
                                # Create intake
                                intake = MedicationIntake.objects.create(
                                    medication=medication,
                                    scheduled_time=scheduled_time,
                                    status='missed'  # Initially missed, will be updated when taken
                                )
                                
                                created_count += 1
                                
                            except ValueError:
                                logger.error(f"Invalid time format: {time_str}")
                
                elif medication.frequency_unit == 'weekly':
                    # Weekly medication
                    days = medication.specific_times or [0]  # Default to Monday (0)
                    hour = 8  # Default to 8 AM
                    
                    for day_of_week in days:
                        # Find next occurrence of this day
                        days_ahead = (day_of_week - today.weekday()) % 7
                        
                        # Skip if it's beyond our look-ahead period
                        if days_ahead >= look_ahead_days:
                            continue
                        
                        intake_date = today + timedelta(days=days_ahead)
                        
                        # Skip if medication ends before this date
                        if medication.end_date and medication.end_date < intake_date and not medication.ongoing:
                            continue
                        
                        # Create scheduled time
                        scheduled_time = timezone.make_aware(
                            datetime.combine(intake_date, datetime.min.time()) + 
                            timedelta(hours=hour)
                        )
                        
                        # Skip times in the past
                        if scheduled_time < now:
                            continue
                        
                        # Create intake
                        intake = MedicationIntake.objects.create(
                            medication=medication,
                            scheduled_time=scheduled_time,
                            status='missed'  # Initially missed, will be updated when taken
                        )
                        
                        created_count += 1
                
                elif medication.frequency_unit == 'monthly':
                    # Monthly medication
                    day = medication.specific_times[0] if medication.specific_times else 1  # Default to 1st day
                    hour = 8  # Default to 8 AM
                    
                    # Check if day exists in current month
                    month_days = [31, 29 if today.year % 4 == 0 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
                    day = min(day, month_days[today.month - 1])
                    
                    # Skip if day has already passed this month
                    if day < today.day:
                        continue
                    
                    intake_date = today.replace(day=day)
                    
                    # Skip if medication ends before this date
                    if medication.end_date and medication.end_date < intake_date and not medication.ongoing:
                        continue
                    
                    # Create scheduled time
                    scheduled_time = timezone.make_aware(
                        datetime.combine(intake_date, datetime.min.time()) + 
                        timedelta(hours=hour)
                    )
                    
                    # Skip times in the past
                    if scheduled_time < now:
                        continue
                    
                    # Create intake
                    intake = MedicationIntake.objects.create(
                        medication=medication,
                        scheduled_time=scheduled_time,
                        status='missed'  # Initially missed, will be updated when taken
                    )
                    
                    created_count += 1
                
            except Exception as med_error:
                logger.error(f"Error generating schedule for medication {medication.id}: {str(med_error)}")
        
        logger.info(f"Created {created_count} scheduled medication intakes")
        return f"Created {created_count} scheduled medication intakes"
    
    except Exception as e:
        logger.error(f"Error generating medication schedules: {str(e)}")
        return f"Error generating medication schedules: {str(e)}"
