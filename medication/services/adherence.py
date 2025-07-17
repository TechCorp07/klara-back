import logging
from datetime import timedelta
from django.utils import timezone
from django.db.models import Avg, Count, Q

logger = logging.getLogger(__name__)

def calculate_adherence(medication, period_type='weekly', force_recalculate=False):
    """
    Calculate medication adherence metrics for a medication.
    
    Args:
        medication: Medication object to calculate adherence for
        period_type: Type of period to calculate (daily, weekly, monthly, quarterly, yearly)
        force_recalculate: Whether to recalculate existing periods
        
    Returns:
        AdherenceRecord object for the current period
    """
    # Import models here to avoid circular imports
    from ..models import MedicationIntake, AdherenceRecord
    
    # Determine period dates based on period_type
    now = timezone.now().date()
    
    if period_type == 'daily':
        period_start = now
        period_end = now
    elif period_type == 'weekly':
        # Start from beginning of week (Monday)
        weekday = now.weekday()
        period_start = now - timedelta(days=weekday)
        period_end = period_start + timedelta(days=6)
    elif period_type == 'monthly':
        # Start from beginning of month
        period_start = now.replace(day=1)
        # Find end of month
        next_month = period_start.replace(day=28) + timedelta(days=4)
        period_end = next_month.replace(day=1) - timedelta(days=1)
    elif period_type == 'quarterly':
        # Start from beginning of quarter
        month = now.month
        quarter_start_month = ((month - 1) // 3) * 3 + 1
        period_start = now.replace(month=quarter_start_month, day=1)
        # End of quarter
        if quarter_start_month == 10:  # Q4
            period_end = now.replace(month=12, day=31)
        else:
            period_end = now.replace(month=quarter_start_month + 2, day=31)
    elif period_type == 'yearly':
        # Start from beginning of year
        period_start = now.replace(month=1, day=1)
        period_end = now.replace(month=12, day=31)
    else:
        # Default to weekly
        weekday = now.weekday()
        period_start = now - timedelta(days=weekday)
        period_end = period_start + timedelta(days=6)
    
    # Check if we already have an adherence record for this period
    existing_record = AdherenceRecord.objects.filter(
        medication=medication,
        patient=medication.patient,
        period_type=period_type,
        period_start=period_start,
        period_end=period_end
    ).first()
    
    if existing_record and not force_recalculate:
        return existing_record
    
    # Create or update adherence record
    if existing_record:
        adherence_record = existing_record
    else:
        adherence_record = AdherenceRecord(
            medication=medication,
            patient=medication.patient,
            period_type=period_type,
            period_start=period_start,
            period_end=period_end
        )
    
    # Update metrics based on medication intakes
    update_from_intakes(adherence_record)
    
    return adherence_record


def update_from_intakes(adherence_record):
    """
    Update adherence record based on medication intakes in the period.
    
    Args:
        adherence_record: AdherenceRecord object to update
        
    Returns:
        Updated AdherenceRecord object
    """
    # Import models here to avoid circular imports
    from ..models import MedicationIntake
    
    # Get all intakes for this medication in the period
    intakes = MedicationIntake.objects.filter(
        medication=adherence_record.medication,
        scheduled_time__date__gte=adherence_record.period_start,
        scheduled_time__date__lte=adherence_record.period_end
    )
    
    # Count doses by status
    adherence_record.doses_scheduled = intakes.count()
    adherence_record.doses_taken = intakes.filter(status=MedicationIntake.Status.TAKEN).count()
    adherence_record.doses_skipped = intakes.filter(status=MedicationIntake.Status.SKIPPED).count()
    adherence_record.doses_missed = intakes.filter(status=MedicationIntake.Status.MISSED).count()
    
    # Calculate adherence rate
    if adherence_record.doses_scheduled > 0:
        adherence_record.adherence_rate = (adherence_record.doses_taken / adherence_record.doses_scheduled) * 100
    else:
        adherence_record.adherence_rate = 0
    
    # Calculate average delay for taken doses
    taken_intakes = intakes.filter(status=MedicationIntake.Status.TAKEN)
    if taken_intakes.exists():
        total_delay = 0
        count = 0
        for intake in taken_intakes:
            if intake.actual_time and intake.scheduled_time:
                delay = (intake.actual_time - intake.scheduled_time).total_seconds() / 60
                if delay > 0:  # Only count positive delays (late)
                    total_delay += delay
                    count += 1
        
        adherence_record.average_delay = total_delay / count if count > 0 else 0
    else:
        adherence_record.average_delay = 0
    
    # Save the record
    adherence_record.save()
    
    return adherence_record


def get_adherence_summary(patient, period_type='weekly', start_date=None, end_date=None):
    """
    Get adherence summary for a patient across all medications.
    
    Args:
        patient: User object to get adherence for
        period_type: Type of period to summarize (daily, weekly, monthly, quarterly, yearly)
        start_date: Start date for summary period (optional)
        end_date: End date for summary period (optional)
        
    Returns:
        Dictionary with adherence metrics
    """
    # Import models here to avoid circular imports
    from ..models import AdherenceRecord
    
    # Get adherence records for this patient
    query = AdherenceRecord.objects.filter(patient=patient, period_type=period_type)
    
    # Apply date filters if provided
    if start_date:
        query = query.filter(period_end__gte=start_date)
    
    if end_date:
        query = query.filter(period_start__lte=end_date)
    
    # Get aggregate metrics
    aggregates = query.aggregate(
        avg_adherence=Avg('adherence_rate'),
        avg_delay=Avg('average_delay'),
        total_scheduled=Count('doses_scheduled'),
        total_taken=Count('doses_taken'),
        total_missed=Count('doses_missed'),
        total_skipped=Count('doses_skipped')
    )
    
    # Get adherence by medication
    medications = {}
    for record in query:
        med_id = record.medication.id
        med_name = record.medication.name
        
        if med_id not in medications:
            medications[med_id] = {
                'id': med_id,
                'name': med_name,
                'adherence_rate': record.adherence_rate,
                'doses_scheduled': record.doses_scheduled,
                'doses_taken': record.doses_taken,
                'doses_missed': record.doses_missed,
                'doses_skipped': record.doses_skipped,
                'average_delay': record.average_delay,
                'period_count': 1
            }
        else:
            # Update existing medication stats
            medications[med_id]['adherence_rate'] += record.adherence_rate
            medications[med_id]['doses_scheduled'] += record.doses_scheduled
            medications[med_id]['doses_taken'] += record.doses_taken
            medications[med_id]['doses_missed'] += record.doses_missed
            medications[med_id]['doses_skipped'] += record.doses_skipped
            medications[med_id]['average_delay'] += record.average_delay
            medications[med_id]['period_count'] += 1
    
    # Calculate averages for each medication
    for med_id in medications:
        period_count = medications[med_id]['period_count']
        if period_count > 0:
            medications[med_id]['adherence_rate'] /= period_count
            medications[med_id]['average_delay'] /= period_count
    
    # Convert to list
    med_list = list(medications.values())
    
    # Sort by adherence rate (lowest first)
    med_list.sort(key=lambda x: x['adherence_rate'])
    
    return {
        'overall_adherence_rate': aggregates['avg_adherence'] or 0,
        'overall_average_delay': aggregates['avg_delay'] or 0,
        'total_doses_scheduled': aggregates['total_scheduled'] or 0,
        'total_doses_taken': aggregates['total_taken'] or 0,
        'total_doses_missed': aggregates['total_missed'] or 0,
        'total_doses_skipped': aggregates['total_skipped'] or 0,
        'medications': med_list
    }


def identify_adherence_issues(patient):
    """
    Identify medications with adherence issues for a patient.
    
    Args:
        patient: User object to check adherence for
        
    Returns:
        List of medications with adherence issues
    """
    # Import models here to avoid circular imports
    from ..models import Medication, AdherenceRecord
    
    # Get active medications for this patient
    medications = Medication.objects.filter(patient=patient, active=True)
    
    # Check adherence for each medication
    issues = []
    
    for medication in medications:
        # Get latest adherence record
        latest_record = AdherenceRecord.objects.filter(
            medication=medication,
            patient=patient
        ).order_by('-period_end').first()
        
        if not latest_record:
            # No adherence data
            issues.append({
                'medication': medication,
                'issue_type': 'no_data',
                'message': 'No adherence data recorded',
                'severity': 'medium'
            })
            continue
        
        # Check adherence rate
        if latest_record.adherence_rate < 50:
            issues.append({
                'medication': medication,
                'issue_type': 'low_adherence',
                'message': f'Low adherence rate: {latest_record.adherence_rate:.1f}%',
                'severity': 'high',
                'adherence_rate': latest_record.adherence_rate
            })
        elif latest_record.adherence_rate < 75:
            issues.append({
                'medication': medication,
                'issue_type': 'moderate_adherence',
                'message': f'Moderate adherence rate: {latest_record.adherence_rate:.1f}%',
                'severity': 'medium',
                'adherence_rate': latest_record.adherence_rate
            })
        
        # Check average delay
        if latest_record.average_delay > 120:  # More than 2 hours late
            issues.append({
                'medication': medication,
                'issue_type': 'high_delay',
                'message': f'High average delay: {latest_record.average_delay:.1f} minutes',
                'severity': 'high',
                'average_delay': latest_record.average_delay
            })
        elif latest_record.average_delay > 60:  # More than 1 hour late
            issues.append({
                'medication': medication,
                'issue_type': 'moderate_delay',
                'message': f'Moderate average delay: {latest_record.average_delay:.1f} minutes',
                'severity': 'medium',
                'average_delay': latest_record.average_delay
            })
    
    return issues
