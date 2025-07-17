# signals.py in healthcare app

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings

from .models import (
    MedicalRecord, Condition, MedicationIntake, LabResult,
    VitalSign, HealthDataConsent, RareConditionRegistry
)

User = get_user_model()

@receiver(post_save, sender=User)
def add_default_health_data_consent(sender, instance, created, **kwargs):
    """
    Create default health data consent settings when a patient is created.
    """
    if created and instance.role == 'patient':
        from .models import HealthDataConsent
        
        # Create default consent entries with consented=False
        for consent_type, _ in HealthDataConsent.CONSENT_TYPES:
            HealthDataConsent.objects.create(
                patient=instance,
                consent_type=consent_type,
                consented=False
            )

@receiver(post_save, sender=Condition)
def update_medical_record_rare_condition_flag(sender, instance, **kwargs):
    """
    Update the medical record's has_rare_condition flag when a condition is marked as rare.
    """
    if instance.is_rare_condition and instance.medical_record:
        medical_record = instance.medical_record
        if not medical_record.has_rare_condition:
            medical_record.has_rare_condition = True
            medical_record.save(update_fields=['has_rare_condition'])
            
            # Notify patient's providers about rare condition
            try:
                if medical_record.primary_physician and medical_record.primary_physician.email:
                    send_mail(
                        subject=f"Rare Condition Identified: {instance.name}",
                        message=f"""
                        A rare condition has been identified for your patient {medical_record.patient.get_full_name()}.
                        
                        Condition: {instance.name}
                        Diagnosed Date: {instance.diagnosed_date}
                        Status: {instance.get_status_display()}
                        
                        Please review the patient's medical record for more details.
                        """,
                        from_email=settings.EMAIL_HOST_USER,
                        recipient_list=[medical_record.primary_physician.email],
                        fail_silently=True,
                    )
            except Exception:
                # Don't let email errors block the save
                pass

@receiver(post_save, sender=MedicationIntake)
def check_medication_adherence(sender, instance, created, **kwargs):
    """
    Track medication adherence and send notifications for missed doses.
    """
    if created and instance.skipped and instance.medication:
        # Alert relevant parties about skipped medication
        try:
            medication = instance.medication
            medical_record = medication.medical_record
            patient = medical_record.patient
            
            # Send provider notification for critical medications
            if medication.is_specialty_medication or medication.for_rare_condition:
                if medical_record.primary_physician and medical_record.primary_physician.email:
                    send_mail(
                        subject=f"Medication Adherence Alert: {patient.get_full_name()}",
                        message=f"""
                        Your patient {patient.get_full_name()} has missed a dose of {medication.name}.
                        
                        Medication: {medication.name} {medication.dosage}
                        Scheduled Time: {instance.taken_at}
                        Reason: {instance.skip_reason or "No reason provided"}
                        
                        This medication is flagged as: 
                        - Specialty Medication: {"Yes" if medication.is_specialty_medication else "No"}
                        - For Rare Condition: {"Yes" if medication.for_rare_condition else "No"}
                        
                        Please follow up with the patient.
                        """,
                        from_email=settings.EMAIL_HOST_USER,
                        recipient_list=[medical_record.primary_physician.email],
                        fail_silently=True,
                    )
        except Exception:
            # Don't let email errors block the save
            pass

@receiver(post_save, sender=LabResult)
def notify_abnormal_results(sender, instance, created, **kwargs):
    """
    Notify providers about abnormal lab results.
    """
    if created and instance.is_abnormal and instance.lab_test:
        try:
            lab_test = instance.lab_test
            medical_record = lab_test.medical_record
            patient = medical_record.patient
            
            # Send provider notification
            if medical_record.primary_physician and medical_record.primary_physician.email:
                send_mail(
                    subject=f"Abnormal Lab Result: {patient.get_full_name()}",
                    message=f"""
                    Your patient {patient.get_full_name()} has an abnormal lab result.
                    
                    Lab Test: {lab_test.name}
                    Test Component: {instance.test_name}
                    Result: {instance.value} {instance.unit}
                    Reference Range: {instance.reference_range}
                    
                    Please review the result in the patient's record.
                    """,
                    from_email=settings.EMAIL_HOST_USER,
                    recipient_list=[medical_record.primary_physician.email],
                    fail_silently=True,
                )
        except Exception:
            # Don't let email errors block the save
            pass

@receiver(post_save, sender=VitalSign)
def check_critical_vitals(sender, instance, created, **kwargs):
    """
    Monitor for critical vital signs and send alerts.
    """
    if created and instance.is_abnormal and instance.medical_record:
        try:
            medical_record = instance.medical_record
            patient = medical_record.patient
            
            # Send provider notification
            if medical_record.primary_physician and medical_record.primary_physician.email:
                send_mail(
                    subject=f"Critical Vital Sign Alert: {patient.get_full_name()}",
                    message=f"""
                    Your patient {patient.get_full_name()} has a critical vital sign.
                    
                    Vital: {instance.get_measurement_type_display()}
                    Value: {instance.value} {instance.unit}
                    Measured at: {instance.measured_at}
                    Source: {instance.source}
                    
                    Please review the patient's record.
                    """,
                    from_email=settings.EMAIL_HOST_USER,
                    recipient_list=[medical_record.primary_physician.email],
                    fail_silently=True,
                )
        except Exception:
            # Don't let email errors block the save
            pass

@receiver(post_save, sender=HealthDataConsent)
def update_user_consent_flags(sender, instance, created, **kwargs):
    """
    Keep user consent flags in sync with HealthDataConsent records.
    """
    try:
        user = instance.patient
        
        # Update user consent flags
        if instance.consent_type == 'medication_tracking':
            user.medication_adherence_monitoring_consent = instance.consented
            
            if hasattr(user, 'patient_profile'):
                user.patient_profile.medication_adherence_opt_in = instance.consented
                if instance.consented:
                    user.patient_profile.medication_adherence_consent_date = timezone.now()
                user.patient_profile.save(update_fields=['medication_adherence_opt_in', 'medication_adherence_consent_date'])
            
            user.save(update_fields=['medication_adherence_monitoring_consent'])
            
        elif instance.consent_type == 'vitals_monitoring':
            user.vitals_monitoring_consent = instance.consented
            
            if hasattr(user, 'patient_profile'):
                user.patient_profile.vitals_monitoring_opt_in = instance.consented
                if instance.consented:
                    user.patient_profile.vitals_monitoring_consent_date = timezone.now()
                user.patient_profile.save(update_fields=['vitals_monitoring_opt_in', 'vitals_monitoring_consent_date'])
            
            user.save(update_fields=['vitals_monitoring_consent'])
            
        elif instance.consent_type == 'research':
            user.research_consent = instance.consented
            user.save(update_fields=['research_consent'])
            
            # Update medical record research consent
            medical_records = user.medical_records.all()
            for record in medical_records:
                record.research_participation_consent = instance.consented
                if instance.consented:
                    record.research_consent_date = timezone.now()
                record.save(update_fields=['research_participation_consent', 'research_consent_date'])
    
    except Exception:
        # Don't let errors block the save
        pass

@receiver(post_save, sender=User)
def update_healthcare_on_approval(sender, instance, **kwargs):
    """
    Trigger healthcare specific actions when a user is approved.
    """
    if instance.is_approved and hasattr(instance, 'approved_at') and instance.approved_at:
        # Check if this is a recent approval (within last hour)
        recently_approved = instance.approved_at >= timezone.now() - timezone.timedelta(hours=1)
        
        if recently_approved and instance.role == 'patient':
            # Create a medical record for the patient if they don't have one
            try:
                MedicalRecord.objects.get_or_create(
                    patient=instance,
                    defaults={
                        'medical_record_number': f"KLR-{instance.id}-{timezone.now().strftime('%Y%m%d')}",
                        'date_of_birth': instance.date_of_birth,
                        'gender': '',  # Default empty, will need to be updated
                        'created_by': instance.approved_by,
                        'updated_by': instance.approved_by
                    }
                )
            except Exception:
                pass
        
        elif recently_approved and instance.role == 'provider':
            # Send notification to provider about available rare conditions registry
            try:
                rare_conditions_count = RareConditionRegistry.objects.count()
                if rare_conditions_count > 0 and instance.email:
                    send_mail(
                        subject="Welcome to Klararety Healthcare Registry",
                        message=f"""
                        Welcome to the Klararety Healthcare Platform!
                        
                        Your account has been approved and you now have access to our rare conditions registry, 
                        which currently contains information about {rare_conditions_count} rare conditions.
                        
                        You can browse the registry, add patients, and track their conditions in our platform.
                        
                        Thank you for joining Klararety!
                        """,
                        from_email=settings.EMAIL_HOST_USER,
                        recipient_list=[instance.email],
                        fail_silently=True,
                    )
            except Exception:
                pass
