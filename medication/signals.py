from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings

from .models import (
    Medication, Prescription, MedicationIntake,
    SideEffect, DrugInteraction
)
from .services.adherence import calculate_adherence
from .services.reminders import generate_reminders
from .services.interactions import check_interactions


@receiver(post_save, sender=Medication)
def create_medication_reminders(sender, instance, created, **kwargs):
    """
    Create reminders when a medication is created.
    """
    if created:
        # Generate reminders for new medication
        generate_reminders(instance)


@receiver(post_save, sender=Medication)
def check_for_interactions(sender, instance, created, **kwargs):
    """
    Check for drug interactions when a medication is created or updated.
    """
    if instance.active:
        # Get other active medications for this patient
        other_medications = Medication.objects.filter(
            patient=instance.patient,
            active=True
        ).exclude(id=instance.id)
        
        # Check interactions with each medication
        for other_med in other_medications:
            check_interactions(instance, other_med)


@receiver(post_save, sender=MedicationIntake)
def update_adherence_on_intake(sender, instance, created, **kwargs):
    """
    Update adherence records when a medication intake is recorded.
    """
    if created:
        # Update adherence records for this medication
        calculate_adherence(instance.medication)


@receiver(post_save, sender=SideEffect)
def notify_provider_of_side_effect(sender, instance, created, **kwargs):
    """
    Notify provider when a severe side effect is reported.
    """
    if created and instance.severity in ['severe', 'life_threatening'] and instance.medication.prescriber:
        # Send email to prescriber
        prescriber = instance.medication.prescriber
        if prescriber.email:
            try:
                send_mail(
                    subject=f"ALERT: Severe Side Effect Reported for {instance.patient.get_full_name()}",
                    message=f"""
                    A severe side effect has been reported for your patient {instance.patient.get_full_name()}.
                    
                    Medication: {instance.medication.name} {instance.medication.dosage}
                    Side Effect: {instance.description}
                    Severity: {instance.get_severity_display()}
                    Onset Date: {instance.onset_date}
                    
                    Please review this patient's case as soon as possible.
                    """,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[prescriber.email],
                    fail_silently=True
                )
            except Exception as e:
                # Log the error but don't raise it
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Error sending side effect email notification: {str(e)}")


@receiver(post_save, sender=DrugInteraction)
def notify_provider_of_interaction(sender, instance, created, **kwargs):
    """
    Notify provider when a major drug interaction is detected.
    """
    if created and instance.severity in ['major', 'contraindicated']:
        # Send email to involved providers
        provider_emails = set()
        
        if instance.medication_a.prescriber and instance.medication_a.prescriber.email:
            provider_emails.add(instance.medication_a.prescriber.email)
            
        if instance.medication_b.prescriber and instance.medication_b.prescriber.email:
            provider_emails.add(instance.medication_b.prescriber.email)
            
        if provider_emails:
            try:
                send_mail(
                    subject=f"ALERT: Drug Interaction Detected for {instance.patient.get_full_name()}",
                    message=f"""
                    A significant drug interaction has been detected for your patient {instance.patient.get_full_name()}.
                    
                    Medications: 
                    - {instance.medication_a.name} {instance.medication_a.dosage}
                    - {instance.medication_b.name} {instance.medication_b.dosage}
                    
                    Interaction: {instance.description}
                    Severity: {instance.get_severity_display()}
                    
                    Please review this patient's medication regimen as soon as possible.
                    """,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=list(provider_emails),
                    fail_silently=True
                )
                
                # Mark provider as notified
                instance.provider_notified = True
                instance.save(update_fields=['provider_notified'])
                
            except Exception as e:
                # Log the error but don't raise it
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Error sending interaction email notification: {str(e)}")


@receiver(post_save, sender=Prescription)
def link_prescription_to_medication(sender, instance, created, **kwargs):
    """
    Link a prescription to a medication if one exists with matching details.
    """
    if created:
        # Try to find a matching medication
        matching_medications = Medication.objects.filter(
            patient=instance.patient,
            name__iexact=instance.medication_name,
            prescription__isnull=True,  # Only medications without a prescription
            active=True
        )
        
        if matching_medications.exists():
            # Link to the first matching medication
            medication = matching_medications.first()
            medication.prescription = instance
            medication.save(update_fields=['prescription'])
            
            # Update medication with prescription details
            if instance.refills > 0:
                medication.refills_allowed = instance.refills
                medication.refills_remaining = instance.refills
                medication.save(update_fields=['refills_allowed', 'refills_remaining'])


@receiver(pre_save, sender=Prescription)
def check_prescription_expiration(sender, instance, **kwargs):
    """
    Check if a prescription is expired and update status accordingly.
    """
    if instance.pk:  # Only for existing prescriptions
        # Check for expiration
        if instance.expiration_date and instance.expiration_date < timezone.now().date():
            if instance.status not in [Prescription.Status.EXPIRED, Prescription.Status.COMPLETED, Prescription.Status.CANCELLED]:
                instance.status = Prescription.Status.EXPIRED


@receiver(pre_save, sender=Medication)
def update_medication_active_status(sender, instance, **kwargs):
    """
    Update medication active status based on end date.
    """
    # If end date is in the past and not ongoing, set active to False
    if instance.end_date and instance.end_date < timezone.now().date() and not instance.ongoing:
        instance.active = False
