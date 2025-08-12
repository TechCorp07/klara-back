# telemedicine/services/notification_service.py
import logging
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from typing import Dict, List, Any, Optional
from ..models import Appointment, Consultation
from communication.services import NotificationService

logger = logging.getLogger(__name__)

class TelemedicineNotificationService:
    """
    Enhanced notification service for telemedicine appointments.
    Specialized for rare disease patients with caregiver and family notifications.
    """

    def __init__(self):
        self.notification_service = NotificationService()

    def send_appointment_confirmation(self, appointment: Appointment) -> bool:
        """Send appointment confirmation with rare disease specific information."""
        try:
            patient = appointment.patient
            
            # Prepare notification data
            notification_data = {
                'appointment_id': str(appointment.id),
                'patient_name': patient.get_full_name(),
                'provider_name': appointment.provider.get_full_name(),
                'appointment_type': appointment.get_appointment_type_display(),
                'scheduled_time': appointment.scheduled_time.isoformat(),
                'duration': appointment.duration_minutes,
                'is_telemedicine': appointment.is_telemedicine,
                'rare_condition_focus': self._is_rare_condition_appointment(appointment)
            }
            
            # Send to patient
            patient_success = self._send_patient_confirmation(patient, notification_data)
            
            # Send to authorized caregivers
            caregiver_success = self._send_caregiver_notifications(patient, notification_data, 'confirmation')
            
            # Send pre-consultation preparation reminders for rare disease patients
            if notification_data['rare_condition_focus']:
                self._schedule_preparation_reminders(appointment)
            
            return patient_success
            
        except Exception as e:
            logger.error(f"Error sending appointment confirmation: {str(e)}")
            return False

    def send_medication_reminder_during_consultation(self, consultation: Consultation, 
                                                   medication_info: Dict[str, Any]) -> bool:
        """Send medication reminder during active consultation."""
        try:
            patient = consultation.patient
            
            # Check if consultation is in progress
            if consultation.status != Consultation.Status.IN_PROGRESS:
                return False
            
            # Prepare reminder data
            reminder_data = {
                'consultation_id': str(consultation.id),
                'medication_name': medication_info['name'],
                'dosage': medication_info['dosage'],
                'scheduled_time': medication_info['scheduled_time'],
                'is_critical': medication_info.get('for_rare_condition', False),
                'provider_name': consultation.provider.get_full_name()
            }
            
            # Send immediate notification to patient
            success = self.notification_service.send_push_notification(
                user=patient,
                title="Medication Reminder During Consultation",
                message=f"Don't forget to take your {medication_info['name']} after your consultation",
                data={
                    'type': 'medication_reminder',
                    'consultation_id': str(consultation.id),
                    'medication_info': reminder_data
                }
            )
            
            # Notify provider about reminder sent
            if success:
                self.notification_service.send_push_notification(
                    user=consultation.provider,
                    title="Medication Reminder Sent",
                    message=f"Reminder sent to {patient.first_name} for {medication_info['name']}",
                    data={
                        'type': 'provider_notification',
                        'consultation_id': str(consultation.id)
                    }
                )
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending medication reminder during consultation: {str(e)}")
            return False
    
    def send_family_consultation_update(self, consultation: Consultation, 
                                      update_type: str, update_data: Dict[str, Any]) -> bool:
        """Send consultation updates to family members for rare disease patients."""
        try:
            patient = consultation.patient
            
            # Check if patient has rare condition and family notification consent
            if not self._is_rare_condition_appointment(consultation.appointment):
                return True  # Not applicable
            
            # Check family notification consent
            if not hasattr(patient, 'patient_profile') or not patient.patient_profile.genetic_data_sharing_consent:
                return True  # No consent for family sharing
            
            # Get family members (this would integrate with your family history system)
            family_members = self._get_authorized_family_members(patient)
            
            if not family_members:
                return True  # No family members to notify
            
            # Prepare family-safe update data (remove PHI)
            family_update_data = {
                'patient_first_name': patient.first_name,
                'consultation_date': consultation.appointment.scheduled_time.date().isoformat(),
                'update_type': update_type,
                'provider_name': consultation.provider.get_full_name(),
                'general_status': update_data.get('general_status', 'Consultation completed'),
                'next_appointment': update_data.get('next_appointment_date')
            }
            
            # Send to family members
            success_count = 0
            for family_member in family_members:
                if self.notification_service.send_email(
                    recipient=family_member['email'],
                    subject=f"Health Update for {patient.first_name}",
                    template='family_consultation_update',
                    context=family_update_data
                ):
                    success_count += 1
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Error sending family consultation update: {str(e)}")
            return False
    
    def send_caregiver_consultation_summary(self, consultation: Consultation, 
                                          care_plan: Dict[str, Any]) -> bool:
        """Send consultation summary and care plan to authorized caregivers."""
        try:
            patient = consultation.patient
            
            # Get authorized caregivers with full access
            authorized_caregivers = []
            if hasattr(patient, 'patient_profile'):
                caregiver_auths = patient.patient_profile.caregiver_authorizations.filter(
                    access_level='FULL'
                )
                authorized_caregivers = [auth.caregiver for auth in caregiver_auths]
            
            if not authorized_caregivers:
                return True  # No caregivers to notify
            
            # Prepare caregiver summary
            caregiver_summary = {
                'patient_name': patient.get_full_name(),
                'consultation_date': consultation.appointment.scheduled_time.isoformat(),
                'provider_name': consultation.provider.get_full_name(),
                'consultation_duration': consultation.duration,
                'medication_changes': care_plan.get('medication_plan', {}).get('changes', []),
                'monitoring_instructions': care_plan.get('monitoring_plan', {}).get('caregiver_tasks', []),
                'next_appointment': care_plan.get('appointment_schedule', {}).get('next_appointment'),
                'emergency_contacts': care_plan.get('emergency_contacts', []),
                'care_instructions': care_plan.get('caregiver_instructions', {})
            }
            
            # Send to each caregiver
            success_count = 0
            for caregiver in authorized_caregivers:
                if self.notification_service.send_email(
                    recipient=caregiver.email,
                    subject=f"Care Plan Update for {patient.first_name}",
                    template='caregiver_consultation_summary',
                    context=caregiver_summary
                ):
                    success_count += 1
                
                # Also send push notification if caregiver has mobile app
                self.notification_service.send_push_notification(
                    user=caregiver,
                    title="New Care Plan Available",
                    message=f"Updated care plan for {patient.first_name} is ready for review",
                    data={
                        'type': 'care_plan_update',
                        'patient_id': str(patient.id),
                        'consultation_id': str(consultation.id)
                    }
                )
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Error sending caregiver consultation summary: {str(e)}")
            return False
    
    def _is_rare_condition_appointment(self, appointment: Appointment) -> bool:
        """Check if appointment is for rare condition patient."""
        return appointment.medical_record and appointment.medical_record.has_rare_condition
    
    def _send_caregiver_notifications(self, patient, notification_data: Dict[str, Any], 
                                    notification_type: str) -> bool:
        """Send notifications to authorized caregivers."""
        
        if not hasattr(patient, 'patient_profile'):
            return True
        
        # Get caregivers with scheduling access
        caregiver_auths = patient.patient_profile.caregiver_authorizations.filter(
            access_level__in=['FULL', 'SCHEDULE']
        )
        
        success_count = 0
        for auth in caregiver_auths:
            caregiver = auth.caregiver
            
            # Send email notification
            if self.notification_service.send_email(
                recipient=caregiver.email,
                subject=f"Appointment {notification_type.title()} for {patient.first_name}",
                template=f'caregiver_appointment_{notification_type}',
                context=notification_data
            ):
                success_count += 1
        
        return success_count > 0
    
    def _schedule_preparation_reminders(self, appointment: Appointment):
        """Schedule preparation reminders for rare disease consultations."""
        from ..tasks import send_consultation_preparation_reminder
        
        # Schedule reminder 24 hours before appointment
        reminder_time = appointment.scheduled_time - timedelta(hours=24)
        
        if reminder_time > timezone.now():
            send_consultation_preparation_reminder.apply_async(
                args=[appointment.id],
                eta=reminder_time
            )
        
        # Schedule reminder 2 hours before appointment
        final_reminder_time = appointment.scheduled_time - timedelta(hours=2)
        
        if final_reminder_time > timezone.now():
            send_consultation_preparation_reminder.apply_async(
                args=[appointment.id, True],  # True for final reminder
                eta=final_reminder_time
            )
    
    def _get_authorized_family_members(self, patient) -> List[Dict[str, Any]]:
        """Get family members authorized to receive health updates."""
        # This would integrate with your family history system
        # For now, return empty list - implement based on your family data structure
        return []

    def send_appointment_reminder(self, appointment: Appointment) -> bool:
        """Send appointment reminder 24 hours before scheduled time."""
        try:
            patient = appointment.patient
            
            # Prepare reminder data
            notification_data = {
                'appointment_id': str(appointment.id),
                'patient_name': patient.get_full_name(),
                'provider_name': appointment.provider.get_full_name(),
                'appointment_type': appointment.get_appointment_type_display(),
                'scheduled_time': appointment.scheduled_time.strftime('%B %d, %Y at %I:%M %p'),
                'duration': appointment.duration_minutes,
                'is_telemedicine': appointment.is_telemedicine,
                'rare_condition_focus': self._is_rare_condition_appointment(appointment)
            }
            
            success = True
            
            # Create in-app notification
            try:
                self.notification_service.create_notification(
                    user=patient,
                    title="Upcoming Appointment Reminder",
                    message=f"You have an appointment with {appointment.provider.get_full_name()} on {notification_data['scheduled_time']}",
                    notification_type='appointment_reminder',
                    related_object_id=appointment.id,
                    related_object_type='appointment'
                )
            except Exception as e:
                logger.error(f"Failed to create in-app notification: {str(e)}")
                success = False
            
            # Send email using standalone function
            try:
                from communication.services.notification_service import send_email_notification
                send_email_notification(
                    user=patient,
                    title=f"Appointment Reminder - {appointment.scheduled_time.strftime('%B %d')}",
                    message=f"Reminder: You have an appointment with {appointment.provider.get_full_name()} on {notification_data['scheduled_time']}",
                    notification_type='appointment_reminder'
                )
            except Exception as e:
                logger.error(f"Failed to send email reminder: {str(e)}")
            
            # Mark reminder as sent
            if success:
                appointment.reminder_sent = True
                appointment.reminder_sent_time = timezone.now()
                appointment.save(update_fields=['reminder_sent', 'reminder_sent_time'])
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending appointment reminder: {str(e)}")
            return False

    def _send_patient_confirmation(self, patient, notification_data: Dict[str, Any]) -> bool:
        """Send appointment confirmation to patient."""
        try:
            success = True
            
            # Create in-app notification
            try:
                self.notification_service.create_notification(
                    user=patient,
                    title="Appointment Confirmed",
                    message=f"Your {notification_data['appointment_type']} with {notification_data['provider_name']} is confirmed for {notification_data['scheduled_time']}",
                    notification_type='appointment_confirmation',
                    related_object_id=notification_data['appointment_id'],
                    related_object_type='appointment'
                )
            except Exception as e:
                logger.error(f"Failed to create confirmation notification: {str(e)}")
                success = False
            
            # Send email using standalone function
            try:
                from communication.services.notification_service import send_email_notification
                send_email_notification(
                    user=patient,
                    title="Appointment Confirmation",
                    message=f"Your {notification_data['appointment_type']} with {notification_data['provider_name']} is confirmed",
                    notification_type='appointment_confirmation'
                )
            except Exception as e:
                logger.error(f"Failed to send confirmation email: {str(e)}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending patient confirmation: {str(e)}")
            return False
        
    def send_appointment_confirmation_with_calendar(self, appointment: Appointment) -> bool:
        """Enhanced confirmation that includes calendar invite."""
        try:
            # Use existing confirmation method
            confirmation_sent = self.send_appointment_confirmation(appointment)
            
            # Add calendar invite if telemedicine and has consultation
            consultation = appointment.consultations.first()
            if appointment.is_telemedicine and consultation and consultation.join_url:
                from .calendar_service import CalendarService
                CalendarService.send_calendar_invite(
                    appointment=appointment,
                    meeting_url=consultation.join_url,
                    meeting_id=consultation.meeting_id
                )
            
            return confirmation_sent
            
        except Exception as e:
            logger.error(f"Enhanced confirmation failed: {str(e)}")
            return False


telemedicine_notifications = TelemedicineNotificationService()