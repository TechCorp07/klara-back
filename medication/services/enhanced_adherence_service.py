# medication/services/enhanced_adherence_service.py
from datetime import timedelta
from django.utils import timezone
from django.db.models import Q, Avg, Count
from typing import Dict, List, Optional
from django.contrib.auth import get_user_model
import logging

from ..models import Medication, MedicationIntake, AdherenceRecord
from wearables.models import WearableIntegration, NotificationDelivery
from wearables.services.notification_service import WearableNotificationService

User = get_user_model()
logger = logging.getLogger(__name__)

class EnhancedAdherenceService:
    """
    Intelligent medication adherence service that builds on your existing models.
    Uses AI-driven insights to optimize reminder timing and patient engagement.
    """
    
    @classmethod
    def create_intelligent_reminder_schedule(cls, medication: Medication) -> Dict:
        """
        Create personalized reminder schedule based on patient's historical adherence patterns.
        Integrates with your existing MedicationIntake model.
        """
        patient = medication.patient
        
        # Analyze historical adherence patterns
        historical_data = MedicationIntake.objects.filter(
            medication__patient=patient,
            scheduled_time__gte=timezone.now() - timedelta(days=90)
        ).order_by('scheduled_time')
        
        # Calculate optimal reminder timing
        reminder_schedule = {
            'medication_id': medication.id,
            'patient_id': patient.id,
            'optimal_times': [],
            'risk_factors': [],
            'personalization_data': {}
        }
        
        if historical_data.exists():
            # Analyze when patient typically takes medications
            successful_intakes = historical_data.filter(status=MedicationIntake.Status.TAKEN)
            
            if successful_intakes.exists():
                # Calculate average delay patterns
                delay_patterns = []
                for intake in successful_intakes:
                    if intake.actual_time and intake.scheduled_time:
                        delay_minutes = (intake.actual_time - intake.scheduled_time).total_seconds() / 60
                        delay_patterns.append({
                            'hour': intake.scheduled_time.hour,
                            'delay_minutes': delay_minutes,
                            'day_of_week': intake.scheduled_time.weekday()
                        })
                
                # Identify optimal reminder times
                reminder_schedule['optimal_times'] = cls._calculate_optimal_reminder_times(
                    delay_patterns, medication.frequency
                )
                
                # Identify risk factors
                reminder_schedule['risk_factors'] = cls._identify_adherence_risk_factors(
                    historical_data, patient
                )
        
        # Default schedule for new patients
        if not reminder_schedule['optimal_times']:
            reminder_schedule['optimal_times'] = cls._create_default_schedule(medication)
        
        # Save schedule to medication model
        medication.adherence_schedule = reminder_schedule
        medication.save(update_fields=['adherence_schedule'])
        
        return reminder_schedule
    
    @classmethod
    def send_intelligent_reminder(cls, medication: Medication, reminder_type: str = 'standard') -> bool:
        """
        Send personalized medication reminder using your existing notification system.
        """
        patient = medication.patient
        
        # Check if patient has connected wearable devices
        wearable_devices = WearableIntegration.objects.filter(
            user=patient,
            status=WearableIntegration.ConnectionStatus.CONNECTED
        )
        
        # Customize message based on medication type and patient preferences
        message_content = cls._generate_personalized_message(medication, reminder_type)
        
        success_count = 0
        
        # Send to wearable devices first (highest engagement)
        for device in wearable_devices:
            if cls._should_use_device_for_reminder(device, reminder_type):
                success = WearableNotificationService.send_watch_notification(
                    device_id=device.platform_user_id,
                    title=f"💊 {medication.name} Reminder",
                    message=message_content['wearable'],
                    medication_id=str(medication.id),
                    is_critical=medication.for_rare_condition
                )
                
                if success:
                    success_count += 1
                    # Log notification delivery
                    NotificationDelivery.objects.create(
                        integration=device,
                        user=patient,
                        notification_type=NotificationDelivery.NotificationType.MEDICATION_REMINDER,
                        title=f"💊 {medication.name} Reminder",
                        message=message_content['wearable'],
                        success=True,
                        sent_at=timezone.now(),
                        medication_id=str(medication.id)
                    )
        
        # Send SMS/Email backup if configured
        if patient.notification_preferences.get('sms_backup', False):
            # Integration with your SMS service
            success = cls._send_sms_reminder(patient, message_content['sms'])
            if success:
                success_count += 1
        
        if patient.notification_preferences.get('email_backup', False):
            # Integration with your email service
            success = cls._send_email_reminder(patient, message_content['email'])
            if success:
                success_count += 1
        
        # Update last reminded timestamp
        medication.last_reminded_at = timezone.now()
        medication.save(update_fields=['last_reminded_at'])
        
        return success_count > 0
    
    @classmethod
    def analyze_adherence_trends(cls, patient_id: int, days: int = 30) -> Dict:
        """
        Analyze adherence trends for dashboard insights.
        Uses your existing AdherenceRecord model.
        """
        patient = User.objects.get(id=patient_id)
        start_date = timezone.now().date() - timedelta(days=days)
        
        # Get adherence records
        adherence_records = AdherenceRecord.objects.filter(
            patient=patient,
            period_start__gte=start_date
        ).order_by('period_start')
        
        # Calculate trends
        if not adherence_records.exists():
            return {'status': 'no_data', 'message': 'No adherence data available'}
        
        # Calculate key metrics
        avg_adherence = adherence_records.aggregate(
            avg_rate=Avg('adherence_rate')
        )['avg_rate'] or 0
        
        # Trend analysis
        recent_records = adherence_records.filter(
            period_start__gte=timezone.now().date() - timedelta(days=14)
        )
        older_records = adherence_records.filter(
            period_start__lt=timezone.now().date() - timedelta(days=14)
        )
        
        recent_avg = recent_records.aggregate(avg_rate=Avg('adherence_rate'))['avg_rate'] or 0
        older_avg = older_records.aggregate(avg_rate=Avg('adherence_rate'))['avg_rate'] or 0
        
        trend_direction = 'stable'
        if recent_avg > older_avg + 5:
            trend_direction = 'improving'
        elif recent_avg < older_avg - 5:
            trend_direction = 'declining'
        
        # Identify problematic medications
        problematic_meds = []
        for record in adherence_records:
            if record.adherence_rate < 80:  # Below 80% adherence
                problematic_meds.append({
                    'medication_name': record.medication.name,
                    'adherence_rate': record.adherence_rate,
                    'period': record.period_start.strftime('%Y-%m-%d')
                })
        
        return {
            'status': 'success',
            'overall_adherence': round(avg_adherence, 1),
            'trend_direction': trend_direction,
            'trend_change': round(recent_avg - older_avg, 1),
            'total_medications': adherence_records.values('medication').distinct().count(),
            'problematic_medications': problematic_meds[:5],  # Top 5 problematic
            'recommendations': cls._generate_adherence_recommendations(
                avg_adherence, trend_direction, problematic_meds
            )
        }
    
    @classmethod
    def create_adherence_intervention(cls, patient_id: int, medication_id: int) -> Dict:
        """
        Create targeted intervention for patients with poor adherence.
        """
        
        patient = User.objects.get(id=patient_id)
        medication = Medication.objects.get(id=medication_id)
        
        # Analyze current adherence
        recent_adherence = AdherenceRecord.objects.filter(
            patient=patient,
            medication=medication,
            period_start__gte=timezone.now().date() - timedelta(days=30)
        ).aggregate(avg_rate=Avg('adherence_rate'))['avg_rate'] or 0
        
        # Determine intervention strategy
        intervention_strategy = {
            'patient_id': patient_id,
            'medication_id': medication_id,
            'current_adherence': recent_adherence,
            'intervention_type': 'standard',
            'actions': []
        }
        
        if recent_adherence < 50:
            intervention_strategy['intervention_type'] = 'intensive'
            intervention_strategy['actions'] = [
                'increase_reminder_frequency',
                'caregiver_notification',
                'provider_alert',
                'simplified_dosing_consultation'
            ]
        elif recent_adherence < 80:
            intervention_strategy['intervention_type'] = 'moderate'
            intervention_strategy['actions'] = [
                'personalized_reminders',
                'educational_content',
                'progress_tracking'
            ]
        else:
            intervention_strategy['intervention_type'] = 'maintenance'
            intervention_strategy['actions'] = [
                'positive_reinforcement',
                'continue_current_strategy'
            ]
        
        return intervention_strategy
    
    # Helper methods
    @classmethod
    def _calculate_optimal_reminder_times(cls, delay_patterns: List[Dict], frequency: str) -> List[Dict]:
        """Calculate optimal reminder times based on historical data."""
        if not delay_patterns:
            return []
        
        # Group by hour and calculate average successful timing
        hour_performance = {}
        for pattern in delay_patterns:
            hour = pattern['hour']
            delay = pattern['delay_minutes']
            
            if hour not in hour_performance:
                hour_performance[hour] = {'delays': [], 'success_rate': 0}
            
            hour_performance[hour]['delays'].append(delay)
        
        # Calculate success metrics for each hour
        optimal_times = []
        for hour, data in hour_performance.items():
            avg_delay = sum(data['delays']) / len(data['delays'])
            success_rate = len([d for d in data['delays'] if d < 30]) / len(data['delays'])
            
            optimal_times.append({
                'hour': hour,
                'recommended_reminder_offset': max(0, int(avg_delay - 15)),  # 15 min buffer
                'success_probability': success_rate,
                'sample_size': len(data['delays'])
            })
        
        return sorted(optimal_times, key=lambda x: x['success_probability'], reverse=True)
    
    @classmethod
    def _identify_adherence_risk_factors(cls, historical_data, patient) -> List[str]:
        """Identify factors that contribute to poor adherence."""
        risk_factors = []
        
        # Analyze day-of-week patterns
        weekday_adherence = {}
        for intake in historical_data:
            day = intake.scheduled_time.weekday()
            if day not in weekday_adherence:
                weekday_adherence[day] = {'total': 0, 'taken': 0}
            
            weekday_adherence[day]['total'] += 1
            if intake.status == MedicationIntake.Status.TAKEN:
                weekday_adherence[day]['taken'] += 1
        
        # Check for weekend effect
        weekend_rates = []
        weekday_rates = []
        
        for day, data in weekday_adherence.items():
            if data['total'] > 0:
                rate = data['taken'] / data['total']
                if day in [5, 6]:  # Saturday, Sunday
                    weekend_rates.append(rate)
                else:
                    weekday_rates.append(rate)
        
        if weekend_rates and weekday_rates:
            avg_weekend = sum(weekend_rates) / len(weekend_rates)
            avg_weekday = sum(weekday_rates) / len(weekday_rates)
            
            if avg_weekend < avg_weekday - 0.1:  # 10% worse on weekends
                risk_factors.append('weekend_adherence_drop')
        
        # Check for time-of-day issues
        missed_intakes = historical_data.filter(status=MedicationIntake.Status.MISSED)
        if missed_intakes.count() > historical_data.count() * 0.2:  # >20% missed
            risk_factors.append('high_miss_rate')
        
        # Check for complex medication regimen
        active_medications = Medication.objects.filter(
            patient=patient,
            active=True
        ).count()
        
        if active_medications > 5:
            risk_factors.append('complex_regimen')
        
        return risk_factors
    
    @classmethod
    def _create_default_schedule(cls, medication: Medication) -> List[Dict]:
        """Create default reminder schedule for new medications."""
        frequency = medication.frequency.lower()
        
        if 'once' in frequency or 'daily' in frequency:
            return [{'hour': 9, 'recommended_reminder_offset': 30}]
        elif 'twice' in frequency:
            return [
                {'hour': 9, 'recommended_reminder_offset': 30},
                {'hour': 21, 'recommended_reminder_offset': 30}
            ]
        elif 'three times' in frequency or 'tid' in frequency:
            return [
                {'hour': 8, 'recommended_reminder_offset': 30},
                {'hour': 14, 'recommended_reminder_offset': 30},
                {'hour': 20, 'recommended_reminder_offset': 30}
            ]
        else:
            return [{'hour': 9, 'recommended_reminder_offset': 30}]
    
    @classmethod
    def _generate_personalized_message(cls, medication: Medication, reminder_type: str) -> Dict[str, str]:
        """Generate personalized reminder messages."""
        patient_name = medication.patient.first_name or "there"
        med_name = medication.name
        
        base_messages = {
            'wearable': f"Hi {patient_name}! Time for your {med_name}. Tap to confirm when taken.",
            'sms': f"Medication reminder: Please take your {med_name} as prescribed. Reply TAKEN when completed.",
            'email': f"Hello {patient_name},\n\nThis is a reminder to take your {med_name}. Please follow your prescribed dosage instructions."
        }
        
        # Customize for rare disease medications
        if medication.for_rare_condition:
            base_messages['wearable'] = f"💊 Important: Time for {med_name}. This medication is crucial for your treatment."
            base_messages['sms'] = f"IMPORTANT: Time for your {med_name}. This rare disease medication is critical for your health."
        
        return base_messages
    
    @classmethod
    def _should_use_device_for_reminder(cls, device: WearableIntegration, reminder_type: str) -> bool:
        """Determine if device should be used for this reminder type."""
        # Always use smartwatches for critical reminders
        if reminder_type == 'critical':
            return True
        
        # Check device-specific preferences
        device_prefs = device.notification_preferences or {}
        return device_prefs.get('medication_reminders', True)
    
    @classmethod
    def _send_sms_reminder(cls, patient, message: str) -> bool:
        """Send SMS reminder (integrate with your SMS service)."""
        # Placeholder for SMS integration
        logger.info(f"SMS reminder sent to {patient.email}: {message}")
        return True
    
    @classmethod
    def _send_email_reminder(cls, patient, message: str) -> bool:
        """Send email reminder (integrate with your email service)."""
        # Placeholder for email integration
        logger.info(f"Email reminder sent to {patient.email}: {message}")
        return True
    
    @classmethod
    def _generate_adherence_recommendations(cls, avg_adherence: float, trend: str, problematic_meds: List) -> List[str]:
        """Generate actionable recommendations for improving adherence."""
        recommendations = []
        
        if avg_adherence < 70:
            recommendations.append("Consider simplifying your medication schedule with your provider")
            recommendations.append("Set up medication alarms on multiple devices")
        
        if trend == 'declining':
            recommendations.append("Schedule a medication review with your healthcare provider")
            recommendations.append("Consider using a pill organizer or medication app")
        
        if len(problematic_meds) > 2:
            recommendations.append("Focus on improving adherence for your most critical medications first")
        
        if not recommendations:
            recommendations.append("Great job! Continue your current medication routine")
        
        return recommendations