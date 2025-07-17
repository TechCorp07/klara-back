import logging
import datetime
from django.db import transaction
from django.utils import timezone
from django.conf import settings
from django.core.exceptions import ValidationError
from ..models import Appointment, ProviderAvailability

logger = logging.getLogger(__name__)

class SchedulingException(Exception):
    """Exception for scheduling errors."""
    pass


def check_provider_availability(provider, start_time, end_time, appointment_type=None, appointment_id=None):
    """
    Check if a provider is available during the specified time slot.
    
    Args:
        provider: Provider user object
        start_time: Start datetime of the requested slot
        end_time: End datetime of the requested slot
        appointment_type: Type of appointment (optional)
        appointment_id: ID of appointment being rescheduled (to exclude from conflicts)
    
    Returns:
        tuple: (bool: is_available, dict: availability_info)
    """
    try:
        # Validate input
        if end_time <= start_time:
            raise SchedulingException("End time must be after start time")
            
        # Check if time is in the past
        now = timezone.now()
        if start_time < now:
            return False, {'error': 'Cannot schedule appointments in the past'}
        
        # Get provider's availability blocks that overlap with the requested time
        availability_blocks = ProviderAvailability.objects.filter(
            provider=provider,
            start_time__lt=end_time,
            end_time__gt=start_time,
            is_available=True
        )
        
        # Check if any matching availability blocks exist
        if not availability_blocks.exists():
            return False, {'error': 'Provider has no availability during this time'}
        
        # Filter blocks by appointment type if specified
        if appointment_type:
            valid_blocks = []
            for block in availability_blocks:
                if not block.appointment_types or appointment_type in block.appointment_types:
                    valid_blocks.append(block)
                    
            if not valid_blocks:
                return False, {'error': f'Provider is not available for {appointment_type} appointments during this time'}
            
            availability_blocks = valid_blocks
        
        # Check for conflicting appointments
        conflicting_appointments = Appointment.objects.filter(
            provider=provider,
            scheduled_time__lt=end_time,
            end_time__gt=start_time,
            status__in=['scheduled', 'confirmed', 'in_progress']
        )
        
        # Exclude the current appointment if we're rescheduling
        if appointment_id:
            conflicting_appointments = conflicting_appointments.exclude(id=appointment_id)
        
        if conflicting_appointments.exists():
            return False, {'error': 'Provider has conflicting appointments during this time'}
        
        # Find the best matching availability block
        best_block = None
        for block in availability_blocks:
            # Check if block is fully booked
            if block.is_booked:
                continue
                
            # Prefer blocks that most closely match the requested time
            if not best_block or (
                start_time >= block.start_time and 
                end_time <= block.end_time
            ):
                best_block = block
        
        if not best_block:
            return False, {'error': 'All matching availability blocks are fully booked'}
        
        return True, {'availability_block': best_block}
        
    except Exception as e:
        logger.error(f"Error checking provider availability: {str(e)}")
        raise SchedulingException(f"Error checking provider availability: {str(e)}")


def get_available_slots(provider, date, appointment_type=None, duration_minutes=30):
    """
    Get available appointment slots for a provider on a specific date.
    
    Args:
        provider: Provider user object
        date: Date to check availability for
        appointment_type: Type of appointment (optional)
        duration_minutes: Duration of appointment in minutes
    
    Returns:
        list: List of available time slots as dictionaries with start and end times
    """
    try:
        # Convert date to datetime range for the full day
        start_datetime = timezone.make_aware(datetime.datetime.combine(date, datetime.time.min))
        end_datetime = timezone.make_aware(datetime.datetime.combine(date, datetime.time.max))
        
        # Get all availability blocks for this provider on this date
        availability_blocks = ProviderAvailability.objects.filter(
            provider=provider,
            start_time__date=date,
            is_available=True
        ).order_by('start_time')
        
        # Filter blocks by appointment type if specified
        if appointment_type:
            filtered_blocks = []
            for block in availability_blocks:
                if not block.appointment_types or appointment_type in block.appointment_types:
                    filtered_blocks.append(block)
            
            availability_blocks = filtered_blocks
        
        # Get existing appointments for this provider on this date
        existing_appointments = Appointment.objects.filter(
            provider=provider,
            scheduled_time__date=date,
            status__in=['scheduled', 'confirmed', 'in_progress']
        ).order_by('scheduled_time')
        
        # Convert existing appointments to busy time ranges
        busy_ranges = [(appt.scheduled_time, appt.end_time) for appt in existing_appointments]
        
        # Calculate available slots
        available_slots = []
        
        for block in availability_blocks:
            # Skip fully booked blocks
            if block.is_booked:
                continue
                
            # Calculate potential slots within this block
            block_start = block.start_time
            block_end = block.end_time
            
            # Don't offer slots in the past
            now = timezone.now()
            if block_start < now:
                block_start = now
                
            # If the block is entirely in the past, skip it
            if block_end <= now:
                continue
            
            # Create slots of the specified duration
            current = block_start
            while current + datetime.timedelta(minutes=duration_minutes) <= block_end:
                slot_end = current + datetime.timedelta(minutes=duration_minutes)
                
                # Check if this slot overlaps with any busy range
                is_available = True
                for busy_start, busy_end in busy_ranges:
                    # Check for overlap
                    if current < busy_end and slot_end > busy_start:
                        is_available = False
                        break
                
                if is_available:
                    available_slots.append({
                        'start_time': current,
                        'end_time': slot_end,
                        'duration_minutes': duration_minutes,
                        'availability_block_id': block.id
                    })
                
                # Move to next slot start time (use slot duration for granularity)
                current += datetime.timedelta(minutes=block.slot_duration_minutes)
        
        return available_slots
        
    except Exception as e:
        logger.error(f"Error getting available slots: {str(e)}")
        raise SchedulingException(f"Error getting available slots: {str(e)}")


@transaction.atomic
def schedule_appointment(patient, provider, start_time, end_time, appointment_type, 
                       reason=None, medical_record=None, related_condition=None, priority='routine'):
    """
    Schedule a new appointment.
    
    Args:
        patient: Patient user object
        provider: Provider user object
        start_time: Start datetime
        end_time: End datetime
        appointment_type: Type of appointment
        reason: Reason for appointment
        medical_record: Associated medical record (optional)
        related_condition: Related condition (optional)
        priority: Appointment priority (default: routine)
    
    Returns:
        Appointment: Created appointment object
    
    Raises:
        SchedulingException: If scheduling fails
    """
    try:
        # Check if provider is available
        is_available, availability_info = check_provider_availability(
            provider, start_time, end_time, appointment_type
        )
        
        if not is_available:
            raise SchedulingException(availability_info.get('error', 'Provider is not available'))
        
        # Create the appointment
        appointment = Appointment(
            patient=patient,
            provider=provider,
            scheduled_time=start_time,
            end_time=end_time,
            appointment_type=appointment_type,
            reason=reason or "No reason provided",
            status=Appointment.Status.SCHEDULED,
            priority=priority,
            medical_record=medical_record,
            related_condition=related_condition,
            duration_minutes=int((end_time - start_time).total_seconds() / 60),
            availability_block=availability_info.get('availability_block')
        )
        
        # Set the created_by field
        appointment.created_by = patient
        appointment.updated_by = patient
        
        # Validate and save
        appointment.full_clean()
        appointment.save()
        
        logger.info(f"Appointment scheduled: ID {appointment.id} for patient {patient.id} with provider {provider.id}")
        return appointment
        
    except ValidationError as e:
        logger.error(f"Validation error scheduling appointment: {str(e)}")
        raise SchedulingException(f"Validation error: {str(e)}")
    except Exception as e:
        logger.error(f"Error scheduling appointment: {str(e)}")
        raise SchedulingException(f"Error scheduling appointment: {str(e)}")


@transaction.atomic
def reschedule_appointment(appointment, new_start_time, new_end_time, reason=None, updated_by=None):
    """
    Reschedule an existing appointment.
    
    Args:
        appointment: Appointment object to reschedule
        new_start_time: New start datetime
        new_end_time: New end datetime
        reason: Reason for rescheduling
        updated_by: User performing the reschedule
    
    Returns:
        Appointment: Updated appointment object
    
    Raises:
        SchedulingException: If rescheduling fails
    """
    try:
        # Check if appointment can be rescheduled
        if appointment.status in ['completed', 'cancelled', 'no_show']:
            raise SchedulingException(f"Cannot reschedule an appointment with status: {appointment.get_status_display()}")
        
        # Check if provider is available at the new time
        is_available, availability_info = check_provider_availability(
            appointment.provider, new_start_time, new_end_time, 
            appointment.appointment_type, appointment.id
        )
        
        if not is_available:
            raise SchedulingException(availability_info.get('error', 'Provider is not available at the new time'))
        
        # Update appointment
        appointment.scheduled_time = new_start_time
        appointment.end_time = new_end_time
        appointment.status = Appointment.Status.SCHEDULED
        
        # Update duration
        appointment.duration_minutes = int((new_end_time - new_start_time).total_seconds() / 60)
        
        # Update availability block if provided
        if 'availability_block' in availability_info:
            appointment.availability_block = availability_info['availability_block']
        
        # Update notes with reason
        if reason:
            appointment.notes += f"\n\nRescheduled on {timezone.now().strftime('%Y-%m-%d %H:%M')}."
            appointment.notes += f"\nReason: {reason}"
        
        # Set the updated_by field
        if updated_by:
            appointment.updated_by = updated_by
        
        # Validate and save
        appointment.full_clean()
        appointment.save()
        
        # Update any related consultations
        for consultation in appointment.consultations.all():
            if consultation.status not in ['completed', 'cancelled']:
                consultation.status = 'scheduled'
                consultation.save()
        
        logger.info(f"Appointment rescheduled: ID {appointment.id} to {new_start_time}")
        return appointment
        
    except ValidationError as e:
        logger.error(f"Validation error rescheduling appointment: {str(e)}")
        raise SchedulingException(f"Validation error: {str(e)}")
    except Exception as e:
        logger.error(f"Error rescheduling appointment: {str(e)}")
        raise SchedulingException(f"Error rescheduling appointment: {str(e)}")


@transaction.atomic
def cancel_appointment(appointment, reason=None, cancelled_by=None):
    """
    Cancel an appointment.
    
    Args:
        appointment: Appointment object to cancel
        reason: Reason for cancellation
        cancelled_by: User performing the cancellation
    
    Returns:
        Appointment: Cancelled appointment object
    
    Raises:
        SchedulingException: If cancellation fails
    """
    try:
        # Check if appointment can be cancelled
        if appointment.status in ['completed', 'cancelled', 'no_show']:
            raise SchedulingException(f"Cannot cancel an appointment with status: {appointment.get_status_display()}")
        
        # Update appointment
        appointment.status = Appointment.Status.CANCELLED
        
        # Update notes with reason
        appointment.notes += f"\n\nCancelled on {timezone.now().strftime('%Y-%m-%d %H:%M')}."
        if reason:
            appointment.notes += f"\nReason: {reason}"
            
        if cancelled_by:
            appointment.notes += f"\nCancelled by: {cancelled_by.get_full_name()}"
            appointment.updated_by = cancelled_by
        
        # Save changes
        appointment.save()
        
        # Cancel any associated consultations
        for consultation in appointment.consultations.all():
            if consultation.status not in ['completed', 'cancelled']:
                consultation.status = 'cancelled'
                consultation.save()
        
        logger.info(f"Appointment cancelled: ID {appointment.id}")
        return appointment
        
    except Exception as e:
        logger.error(f"Error cancelling appointment: {str(e)}")
        raise SchedulingException(f"Error cancelling appointment: {str(e)}")


def set_provider_availability(provider, start_time, end_time, is_available=True, 
                           appointment_types=None, slot_duration_minutes=15, max_appointments=1):
    """
    Set provider availability for a time period.
    
    Args:
        provider: Provider user object
        start_time: Start datetime
        end_time: End datetime
        is_available: Whether the provider is available during this time
        appointment_types: List of supported appointment types
        slot_duration_minutes: Minimum appointment slot duration
        max_appointments: Maximum appointments per slot
    
    Returns:
        ProviderAvailability: Created or updated availability object
    
    Raises:
        SchedulingException: If setting availability fails
    """
    try:
        # Validate input
        if end_time <= start_time:
            raise SchedulingException("End time must be after start time")
        
        # Create availability block
        availability = ProviderAvailability(
            provider=provider,
            start_time=start_time,
            end_time=end_time,
            is_available=is_available,
            appointment_types=appointment_types or list(dict(Appointment.AppointmentType.choices).keys()),
            slot_duration_minutes=slot_duration_minutes,
            max_appointments=max_appointments
        )
        
        # Validate and save
        availability.full_clean()
        availability.save()
        
        logger.info(f"Provider availability set: {provider.id} from {start_time} to {end_time}")
        return availability
        
    except ValidationError as e:
        logger.error(f"Validation error setting provider availability: {str(e)}")
        raise SchedulingException(f"Validation error: {str(e)}")
    except Exception as e:
        logger.error(f"Error setting provider availability: {str(e)}")
        raise SchedulingException(f"Error setting provider availability: {str(e)}")


def set_recurring_availability(provider, start_time, end_time, recurrence_pattern, 
                            is_available=True, appointment_types=None, 
                            slot_duration_minutes=15, max_appointments=1):
    """
    Set recurring provider availability.
    
    Args:
        provider: Provider user object
        start_time: Start datetime for first occurrence
        end_time: End datetime for first occurrence
        recurrence_pattern: iCal RRULE format string
        is_available: Whether the provider is available during this time
        appointment_types: List of supported appointment types
        slot_duration_minutes: Minimum appointment slot duration
        max_appointments: Maximum appointments per slot
    
    Returns:
        list: Created availability objects
    
    Raises:
        SchedulingException: If setting availability fails
    """
    try:
        # Validate input
        if end_time <= start_time:
            raise SchedulingException("End time must be after start time")
        
        # For now, only create the first occurrence
        # In a real implementation, this would use a third-party library like dateutil.rrule
        # to generate multiple occurrences based on the recurrence pattern
        
        availability = ProviderAvailability(
            provider=provider,
            start_time=start_time,
            end_time=end_time,
            is_available=is_available,
            recurrence_pattern=recurrence_pattern,
            appointment_types=appointment_types or list(dict(Appointment.AppointmentType.choices).keys()),
            slot_duration_minutes=slot_duration_minutes,
            max_appointments=max_appointments
        )
        
        # Validate and save
        availability.full_clean()
        availability.save()
        
        logger.info(f"Recurring provider availability set: {provider.id} with pattern {recurrence_pattern}")
        return [availability]
        
    except ValidationError as e:
        logger.error(f"Validation error setting recurring availability: {str(e)}")
        raise SchedulingException(f"Validation error: {str(e)}")
    except Exception as e:
        logger.error(f"Error setting recurring availability: {str(e)}")
        raise SchedulingException(f"Error setting recurring availability: {str(e)}")


def get_provider_schedule(provider, start_date, end_date=None):
    """
    Get a provider's schedule for a date range.
    
    Args:
        provider: Provider user object
        start_date: Start date
        end_date: End date (defaults to start_date + 7 days)
    
    Returns:
        dict: Schedule information containing availability and appointments
    """
    try:
        # Set default end date if not provided
        if not end_date:
            end_date = start_date + datetime.timedelta(days=7)
            
        # Convert dates to datetime ranges
        start_datetime = timezone.make_aware(datetime.datetime.combine(start_date, datetime.time.min))
        end_datetime = timezone.make_aware(datetime.datetime.combine(end_date, datetime.time.max))
        
        # Get availability blocks
        availability_blocks = ProviderAvailability.objects.filter(
            provider=provider,
            start_time__lt=end_datetime,
            end_time__gt=start_datetime
        ).order_by('start_time')
        
        # Get appointments
        appointments = Appointment.objects.filter(
            provider=provider,
            scheduled_time__lt=end_datetime,
            end_time__gt=start_datetime
        ).order_by('scheduled_time')
        
        # Format response
        schedule = {
            'provider_id': provider.id,
            'provider_name': provider.get_full_name(),
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat(),
            'availability': [
                {
                    'id': block.id,
                    'start_time': block.start_time.isoformat(),
                    'end_time': block.end_time.isoformat(),
                    'is_available': block.is_available,
                    'appointment_types': block.appointment_types,
                    'is_booked': block.is_booked,
                    'recurrence_pattern': block.recurrence_pattern
                }
                for block in availability_blocks
            ],
            'appointments': [
                {
                    'id': appt.id,
                    'patient_name': appt.patient.get_full_name(),
                    'patient_id': appt.patient.id,
                    'start_time': appt.scheduled_time.isoformat(),
                    'end_time': appt.end_time.isoformat(),
                    'appointment_type': appt.appointment_type,
                    'appointment_type_display': appt.get_appointment_type_display(),
                    'status': appt.status,
                    'status_display': appt.get_status_display()
                }
                for appt in appointments
            ]
        }
        
        return schedule
        
    except Exception as e:
        logger.error(f"Error getting provider schedule: {str(e)}")
        raise SchedulingException(f"Error getting provider schedule: {str(e)}")
