import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Count, Avg, Q, F
from django.conf import settings
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class RealTimeAnalyticsService:
    """Real-time analytics for rare disease patients."""
    
    @staticmethod
    def get_medication_adherence_alerts():
        """Get real-time medication adherence alerts."""
        from medication.models import MedicationReminder, AdherenceRecord
        from django.contrib.auth import get_user_model
        
        User = get_user_model()
        
        # Find patients with missed critical medications in last 24 hours
        missed_critical = MedicationReminder.objects.filter(
            scheduled_time__gte=timezone.now() - timedelta(hours=24),
            scheduled_time__lte=timezone.now(),
            is_critical=True,
            medication__for_rare_condition=True,
            times_sent__gt=0
        ).exclude(
            medication__adherence_records__taken_at__date=timezone.now().date()
        )
        
        alerts = []
        for reminder in missed_critical:
            alerts.append({
                'patient_id': reminder.patient.id,
                'patient_name': reminder.patient.get_full_name(),
                'medication': reminder.medication.name,
                'scheduled_time': reminder.scheduled_time,
                'severity': 'CRITICAL',
                'rare_condition': reminder.medication.condition
            })
        
        return alerts
    
    @staticmethod
    def get_wearable_anomalies():
        """Detect anomalies in wearable data for rare disease patients."""
        from wearables.models import WearableData
        from users.models import PatientProfile
        
        # Get patients with rare conditions
        rare_disease_patients = PatientProfile.objects.filter(
            has_rare_condition=True,
            smartwatch_integration_active=True
        )
        
        anomalies = []
        for patient_profile in rare_disease_patients:
            # Check for heart rate anomalies
            recent_hr = WearableData.objects.filter(
                user=patient_profile.user,
                data_type='heart_rate',
                recorded_at__gte=timezone.now() - timedelta(hours=1)
            ).order_by('-recorded_at')[:5]
            
            if recent_hr.count() >= 3:
                avg_hr = sum([float(hr.value) for hr in recent_hr]) / len(recent_hr)
                
                # Define anomaly thresholds based on rare condition
                if avg_hr > 120 or avg_hr < 50:  # Adjust based on condition
                    anomalies.append({
                        'patient_id': patient_profile.user.id,
                        'patient_name': patient_profile.user.get_full_name(),
                        'metric': 'heart_rate',
                        'value': avg_hr,
                        'threshold_breached': 'high' if avg_hr > 120 else 'low',
                        'timestamp': timezone.now(),
                        'requires_immediate_attention': True
                    })
        
        return anomalies
    
    @staticmethod
    def get_emergency_indicators():
        """Get real-time emergency indicators for rare disease patients."""
        from communication.models import Notification
        from telemedicine.models import Appointment
        
        # Recent emergency notifications
        emergency_notifications = Notification.objects.filter(
            notification_type='system',
            title__icontains='emergency',
            created_at__gte=timezone.now() - timedelta(hours=24)
        )
        
        # Urgent appointment requests
        urgent_appointments = Appointment.objects.filter(
            status='requested',
            priority='urgent',
            requested_at__gte=timezone.now() - timedelta(hours=24)
        )
        
        indicators = []
        
        for notification in emergency_notifications:
            indicators.append({
                'type': 'emergency_notification',
                'patient_id': notification.user.id,
                'patient_name': notification.user.get_full_name(),
                'message': notification.message,
                'timestamp': notification.created_at,
                'severity': 'HIGH'
            })
        
        for appointment in urgent_appointments:
            indicators.append({
                'type': 'urgent_appointment',
                'patient_id': appointment.patient.id,
                'patient_name': appointment.patient.get_full_name(),
                'reason': appointment.reason,
                'timestamp': appointment.requested_at,
                'severity': 'MEDIUM'
            })
        
        return indicators