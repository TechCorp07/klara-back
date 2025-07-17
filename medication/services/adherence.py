# medication/services/adherence.py
from django.utils import timezone
from django.db.models import Q, Count, Avg
from datetime import timedelta, date
from typing import Optional, Dict, Any
import logging

from ..models import Medication, MedicationIntake, AdherenceRecord

logger = logging.getLogger(__name__)

def calculate_adherence(medication: Medication, period_type: str = 'weekly', force_recalculate: bool = False) -> Optional[AdherenceRecord]:
    """
    Calculate and store adherence metrics for a medication.
    Critical for rare disease monitoring where adherence directly impacts efficacy.
    """
    if not medication.active:
        return None
    
    # Determine period dates
    today = timezone.now().date()
    
    if period_type == 'daily':
        period_start = today
        period_end = today
    elif period_type == 'weekly':
        period_start = today - timedelta(days=7)
        period_end = today
    elif period_type == 'monthly':
        period_start = today - timedelta(days=30)
        period_end = today
    else:
        raise ValueError(f"Invalid period_type: {period_type}")
    
    # Check if record already exists
    existing_record = AdherenceRecord.objects.filter(
        medication=medication,
        period_type=period_type,
        period_start=period_start,
        period_end=period_end
    ).first()
    
    if existing_record and not force_recalculate:
        return existing_record
    
    # Get intake records for the period
    intakes = MedicationIntake.objects.filter(
        medication=medication,
        scheduled_time__date__gte=period_start,
        scheduled_time__date__lte=period_end
    )
    
    # Calculate metrics
    total_scheduled = intakes.count()
    taken_count = intakes.filter(status=MedicationIntake.Status.TAKEN).count()
    skipped_count = intakes.filter(status=MedicationIntake.Status.SKIPPED).count()
    missed_count = intakes.filter(status=MedicationIntake.Status.MISSED).count()
    
    # Calculate adherence rate
    adherence_rate = (taken_count / total_scheduled * 100) if total_scheduled > 0 else 0
    
    # Calculate average delay for taken doses
    taken_intakes = intakes.filter(
        status=MedicationIntake.Status.TAKEN,
        actual_time__isnull=False
    )
    
    average_delay = 0
    if taken_intakes.exists():
        total_delay = 0
        delay_count = 0
        
        for intake in taken_intakes:
            if intake.actual_time and intake.scheduled_time:
                delay_minutes = (intake.actual_time - intake.scheduled_time).total_seconds() / 60
                if delay_minutes > 0:  # Only count positive delays
                    total_delay += delay_minutes
                    delay_count += 1
        
        average_delay = total_delay / delay_count if delay_count > 0 else 0
    
    # Create or update adherence record
    if existing_record:
        record = existing_record
    else:
        record = AdherenceRecord(
            medication=medication,
            patient=medication.patient,
            period_type=period_type,
            period_start=period_start,
            period_end=period_end
        )
    
    # Update fields
    record.doses_scheduled = total_scheduled
    record.doses_taken = taken_count
    record.doses_skipped = skipped_count
    record.doses_missed = missed_count
    record.adherence_rate = adherence_rate
    record.average_delay = average_delay
    
    record.save()
    
    # Log adherence calculation for rare disease monitoring
    logger.info(f"Adherence calculated for {medication.patient.email} - {medication.name}: {adherence_rate:.1f}%")
    
    # Alert for low adherence on rare disease medications
    if medication.for_rare_condition and adherence_rate < 80:
        _alert_low_adherence(medication, record)
    
    return record

def _alert_low_adherence(medication: Medication, adherence_record: AdherenceRecord):
    """Alert providers and pharmaceutical companies about low adherence for rare disease medications."""
    from communication.tasks import send_adherence_alert
    
    # Send alert to prescriber
    if medication.prescriber:
        send_adherence_alert.delay(
            recipient_id=medication.prescriber.id,
            medication_id=medication.id,
            adherence_rate=adherence_record.adherence_rate,
            alert_type='provider'
        )
    
    # Send alert to pharmaceutical company if consented
    if medication.patient.patient_profile.protocol_adherence_monitoring:
        # Send to pharmaceutical companies monitoring this drug
        send_adherence_alert.delay(
            medication_id=medication.id,
            adherence_rate=adherence_record.adherence_rate,
            alert_type='pharmco'
        )

def get_adherence_trends(patient, days: int = 30) -> Dict[str, Any]:
    """Get adherence trends for dashboard analytics."""
    end_date = timezone.now().date()
    start_date = end_date - timedelta(days=days)
    
    # Get adherence records
    records = AdherenceRecord.objects.filter(
        patient=patient,
        period_start__gte=start_date,
        period_end__lte=end_date
    ).order_by('period_start')
    
    # Calculate overall metrics
    if records.exists():
        avg_adherence = records.aggregate(Avg('adherence_rate'))['adherence_rate__avg']
        trend_data = list(records.values('period_start', 'adherence_rate', 'medication__name'))
    else:
        avg_adherence = 0
        trend_data = []
    
    return {
        'average_adherence': round(avg_adherence, 1) if avg_adherence else 0,
        'trend_data': trend_data,
        'total_medications': patient.medications.filter(active=True).count(),
        'rare_disease_medications': patient.medications.filter(active=True, for_rare_condition=True).count()
    }