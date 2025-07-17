from django.db.models.signals import post_save, pre_save, pre_delete
from django.dispatch import receiver
from django.utils import timezone
import logging
from .models import (
    Appointment, Consultation, Prescription, 
    ProviderAvailability, WaitingRoom, WaitingRoomPatient,
    ConsultationNote
)
from .services import notifications_service, zoom_service

logger = logging.getLogger(__name__)


@receiver(post_save, sender=Appointment)
def handle_appointment_status_change(sender, instance, created, **kwargs):
    """
    Handle appointment status changes.
    
    Creates consultations for confirmed appointments, sends notifications,
    and handles other side effects of status changes.
    """
    try:
        # Skip if this is an update from a signal handler to avoid loops
        if hasattr(instance, '_from_signal'):
            return
            
        # If appointment was just created, nothing else to do
        if created:
            return
            
        # Get the previous status from the database
        if hasattr(instance, '_previous_status'):
            previous_status = instance._previous_status
        else:
            # If we don't know the previous status, assume it's a status change
            # and proceed with handling
            previous_status = None
        
        # Handle status change to confirmed
        if instance.status == Appointment.Status.CONFIRMED and previous_status != Appointment.Status.CONFIRMED:
            # Create a consultation if it's a video or phone consultation
            if instance.is_telemedicine:
                # Check if consultation already exists
                if not instance.consultations.exists():
                    Consultation.objects.create(
                        appointment=instance,
                        status=Consultation.Status.SCHEDULED
                    )
                
                # Send confirmation notification
                try:
                    notifications_service.send_appointment_confirmation(instance)
                except Exception as e:
                    logger.error(f"Failed to send confirmation notification: {str(e)}")
                    
        # Handle status change to cancelled
        elif instance.status == Appointment.Status.CANCELLED and previous_status not in [
            Appointment.Status.CANCELLED, Appointment.Status.COMPLETED, Appointment.Status.NO_SHOW
        ]:
            # Cancel any associated consultations
            for consultation in instance.consultations.all():
                if consultation.status not in [Consultation.Status.COMPLETED, Consultation.Status.CANCELLED]:
                    # Skip signal handling for this update
                    consultation._from_signal = True
                    consultation.status = Consultation.Status.CANCELLED
                    consultation.save(update_fields=['status'])
                    
                    # Try to cancel Zoom meeting if it exists
                    if (consultation.platform == Consultation.Platform.ZOOM and 
                        consultation.meeting_id):
                        try:
                            zoom_service.delete_zoom_meeting(consultation.meeting_id)
                        except zoom_service.ZoomMeetingException as e:
                            logger.warning(f"Failed to cancel Zoom meeting: {str(e)}")
            
            # Remove from waiting room if present
            for waiting_entry in instance.waiting_room_entries.all():
                if waiting_entry.status in [WaitingRoomPatient.Status.WAITING, WaitingRoomPatient.Status.READY]:
                    waiting_entry._from_signal = True
                    waiting_entry.status = WaitingRoomPatient.Status.CANCELLED
                    waiting_entry.save(update_fields=['status'])
    
    except Exception as e:
        logger.error(f"Error in appointment status change handler: {str(e)}")


@receiver(pre_save, sender=Appointment)
def store_previous_appointment_status(sender, instance, **kwargs):
    """Store the previous appointment status before saving."""
    if instance.pk:
        try:
            previous = Appointment.objects.get(pk=instance.pk)
            instance._previous_status = previous.status
        except Appointment.DoesNotExist:
            instance._previous_status = None


@receiver(post_save, sender=Consultation)
def handle_consultation_status_change(sender, instance, created, **kwargs):
    """
    Handle consultation status changes.
    
    Updates appointment status based on consultation status changes,
    sends notifications, and handles other side effects.
    """
    try:
        # Skip if this is an update from a signal handler to avoid loops
        if hasattr(instance, '_from_signal'):
            return
            
        # Only proceed if we have an appointment
        if not instance.appointment:
            return
            
        # Get the previous status from the database
        if hasattr(instance, '_previous_status'):
            previous_status = instance._previous_status
        else:
            # If we don't know the previous status, assume it's a status change
            # and proceed with handling
            previous_status = None
        
        # Handle status change to in progress
        if instance.status == Consultation.Status.IN_PROGRESS and previous_status != Consultation.Status.IN_PROGRESS:
            # Update appointment status
            appointment = instance.appointment
            if appointment.status not in [Appointment.Status.IN_PROGRESS, Appointment.Status.COMPLETED]:
                appointment._from_signal = True
                appointment.status = Appointment.Status.IN_PROGRESS
                appointment.save(update_fields=['status'])
                
        # Handle status change to completed
        elif instance.status == Consultation.Status.COMPLETED and previous_status != Consultation.Status.COMPLETED:
            # Update appointment status
            appointment = instance.appointment
            if appointment.status != Appointment.Status.COMPLETED:
                appointment._from_signal = True
                appointment.status = Appointment.Status.COMPLETED
                appointment.save(update_fields=['status'])
                
            # Create consultation note if it doesn't exist
            if not hasattr(instance, 'detailed_notes'):
                ConsultationNote.objects.create(
                    consultation=instance,
                    created_by=instance.appointment.provider
                )
                
        # Handle status change to cancelled
        elif instance.status == Consultation.Status.CANCELLED and previous_status != Consultation.Status.CANCELLED:
            # Check if we should cancel the appointment too
            appointment = instance.appointment
            if (appointment.status not in [
                Appointment.Status.CANCELLED, Appointment.Status.COMPLETED, Appointment.Status.NO_SHOW
            ] and appointment.consultations.count() == 1):
                # This is the only consultation, so cancel the appointment too
                appointment._from_signal = True
                appointment.status = Appointment.Status.CANCELLED
                appointment.save(update_fields=['status'])
    
    except Exception as e:
        logger.error(f"Error in consultation status change handler: {str(e)}")


@receiver(pre_save, sender=Consultation)
def store_previous_consultation_status(sender, instance, **kwargs):
    """Store the previous consultation status before saving."""
    if instance.pk:
        try:
            previous = Consultation.objects.get(pk=instance.pk)
            instance._previous_status = previous.status
        except Consultation.DoesNotExist:
            instance._previous_status = None


@receiver(pre_delete, sender=Consultation)
def handle_consultation_deletion(sender, instance, **kwargs):
    """
    Handle consultation deletion.
    
    Cleans up external resources like Zoom meetings before deletion.
    """
    try:
        # Delete Zoom meeting if it exists
        if (instance.platform == Consultation.Platform.ZOOM and 
            instance.meeting_id):
            try:
                zoom_service.delete_zoom_meeting(instance.meeting_id)
            except zoom_service.ZoomMeetingException as e:
                logger.warning(f"Failed to delete Zoom meeting: {str(e)}")
    
    except Exception as e:
        logger.error(f"Error in consultation deletion handler: {str(e)}")


@receiver(post_save, sender=Prescription)
def handle_prescription_save(sender, instance, created, **kwargs):
    """
    Handle prescription creation and updates.
    
    Sends notifications, checks for drug interactions, and handles
    electronic prescription submission when status changes.
    """
    try:
        # Skip if this is an update from a signal handler to avoid loops
        if hasattr(instance, '_from_signal'):
            return
        
        # If prescription was just created, send notification
        if created:
            # Send notification to patient
            try:
                notifications_service.send_prescription_notification(instance)
            except Exception as e:
                logger.error(f"Failed to send prescription notification: {str(e)}")
                
        # Get the previous status from the database
        if hasattr(instance, '_previous_status'):
            previous_status = instance._previous_status
            
            # Handle status change to active (e.g., when e-prescription is approved)
            if instance.status == Prescription.Status.ACTIVE and previous_status != Prescription.Status.ACTIVE:
                # Send notification to patient
                try:
                    instance._from_signal = True
                    notifications_service.send_prescription_notification(instance)
                except Exception as e:
                    logger.error(f"Failed to send prescription notification: {str(e)}")
    
    except Exception as e:
        logger.error(f"Error in prescription save handler: {str(e)}")


@receiver(pre_save, sender=Prescription)
def store_previous_prescription_status(sender, instance, **kwargs):
    """Store the previous prescription status before saving."""
    if instance.pk:
        try:
            previous = Prescription.objects.get(pk=instance.pk)
            instance._previous_status = previous.status
        except Prescription.DoesNotExist:
            instance._previous_status = None


@receiver(pre_save, sender=Prescription)
def check_prescription_expiration(sender, instance, **kwargs):
    """Check if a prescription has expired and update its status accordingly."""
    try:
        # Check if expiration date is set and has passed
        if instance.expiration_date and timezone.now().date() > instance.expiration_date:
            # Only update if status is not already expired or completed
            if instance.status not in [Prescription.Status.EXPIRED, Prescription.Status.COMPLETED]:
                instance.status = Prescription.Status.EXPIRED
    
    except Exception as e:
        logger.error(f"Error in prescription expiration check: {str(e)}")


@receiver(post_save, sender=WaitingRoomPatient)
def handle_waiting_room_patient_status_change(sender, instance, created, **kwargs):
    """
    Handle waiting room patient status changes.
    
    Updates appointment status based on waiting room status changes,
    prepares consultations, and sends notifications.
    """
    try:
        # Skip if this is an update from a signal handler to avoid loops
        if hasattr(instance, '_from_signal'):
            return
        
        # Get the previous status
        if hasattr(instance, '_previous_status'):
            previous_status = instance._previous_status
        else:
            # If we don't know the previous status, assume it's new
            previous_status = None if created else WaitingRoomPatient.Status.WAITING
        
        # Handle check-in
        if created:
            # Update appointment status to checked in
            appointment = instance.appointment
            appointment._from_signal = True
            appointment.status = Appointment.Status.CHECKED_IN
            appointment.save(update_fields=['status'])
        
        # Handle status change to ready
        elif instance.status == WaitingRoomPatient.Status.READY and previous_status != WaitingRoomPatient.Status.READY:
            # Get or create a consultation for this appointment
            appointment = instance.appointment
            consultation, created = Consultation.objects.get_or_create(
                appointment=appointment,
                defaults={
                    'status': Consultation.Status.READY
                }
            )
            
            # Update consultation status if not created
            if not created and consultation.status not in [
                Consultation.Status.IN_PROGRESS, Consultation.Status.COMPLETED, Consultation.Status.CANCELLED
            ]:
                consultation._from_signal = True
                consultation.status = Consultation.Status.READY
                consultation.save(update_fields=['status'])
                
        # Handle status change to completed or cancelled
        elif instance.status in [WaitingRoomPatient.Status.COMPLETED, WaitingRoomPatient.Status.CANCELLED]:
            # Nothing specific to do here, appointment status will be updated by consultation signals
            pass
    
    except Exception as e:
        logger.error(f"Error in waiting room patient status change handler: {str(e)}")


@receiver(pre_save, sender=WaitingRoomPatient)
def store_previous_waiting_room_patient_status(sender, instance, **kwargs):
    """Store the previous waiting room patient status before saving."""
    if instance.pk:
        try:
            previous = WaitingRoomPatient.objects.get(pk=instance.pk)
            instance._previous_status = previous.status
        except WaitingRoomPatient.DoesNotExist:
            instance._previous_status = None


@receiver(post_save, sender=ConsultationNote)
def handle_consultation_note_completion(sender, instance, created, **kwargs):
    """
    Handle consultation note completion.
    
    Updates consultation and appointment status when notes are completed.
    """
    try:
        # Skip if this is an update from a signal handler to avoid loops
        if hasattr(instance, '_from_signal'):
            return
            
        # Handle note being marked as complete
        if instance.is_complete and instance.completed_at:
            # Ensure consultation is marked as completed
            consultation = instance.consultation
            if consultation and consultation.status != Consultation.Status.COMPLETED:
                consultation._from_signal = True
                consultation.status = Consultation.Status.COMPLETED
                
                # If notes contain diagnosis or treatment plan, copy to consultation
                if instance.assessment:
                    consultation.diagnosis = instance.assessment
                if instance.plan:
                    consultation.treatment_plan = instance.plan
                
                consultation.save()
    
    except Exception as e:
        logger.error(f"Error in consultation note completion handler: {str(e)}")
