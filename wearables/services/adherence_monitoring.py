#wearables/services/adherence_monitoring.py
from django.utils import timezone
from datetime import timedelta
from typing import Dict, List, Any
import logging

from ..models import WearableMeasurement, WearableIntegration, NotificationDelivery
from medication.models import Medication, MedicationIntake

logger = logging.getLogger(__name__)

class AdherenceMonitoringService:
    """
    Monitor medication adherence through wearable device data.
    Critical for rare disease patients and pharmaceutical companies.
    """
    
    @classmethod
    def monitor_medication_adherence(cls, user, medication: Medication) -> Dict[str, Any]:
        """
        Monitor adherence using wearable data patterns.
        Looks for activity patterns that indicate medication taking.
        """
        try:
            # Get user's active wearable integrations
            integrations = WearableIntegration.objects.filter(
                user=user,
                status=WearableIntegration.ConnectionStatus.CONNECTED
            )
            
            if not integrations.exists():
                return {'success': False, 'message': 'No active wearable integrations'}
            
            # Check recent activity patterns
            now = timezone.now()
            check_window = now - timedelta(hours=2)  # 2-hour window for adherence check
            
            adherence_indicators = []
            
            for integration in integrations:
                # Check for activity patterns that might indicate medication taking
                indicators = cls._analyze_adherence_patterns(integration, medication, check_window, now)
                adherence_indicators.extend(indicators)
            
            # Generate adherence report
            report = cls._generate_adherence_report(medication, adherence_indicators)
            
            # Alert pharmaceutical companies if consented
            if user.patient_profile.protocol_adherence_monitoring:
                cls._notify_pharmaceutical_companies(user, medication, report)
            
            return report
            
        except Exception as e:
            logger.error(f"Error monitoring adherence for {user.email}: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    @classmethod
    def _analyze_adherence_patterns(cls, integration: WearableIntegration, medication: Medication, 
                                  start_time, end_time) -> List[Dict[str, Any]]:
        """Analyze wearable data patterns for adherence indicators."""
        indicators = []
        
        try:
            # Get measurements in the time window
            measurements = WearableMeasurement.objects.filter(
                user=integration.user,
                integration_type=integration.integration_type,
                measured_at__gte=start_time,
                measured_at__lte=end_time
            )
            
            # Look for activity spikes that might indicate getting up to take medication
            activity_measurements = measurements.filter(
                measurement_type__in=[
                    WearableMeasurement.MeasurementType.STEPS,
                    WearableMeasurement.MeasurementType.HEART_RATE,
                    WearableMeasurement.MeasurementType.ACTIVITY
                ]
            ).order_by('measured_at')
            
            # Analyze patterns
            if activity_measurements.exists():
                # Check for movement patterns consistent with medication taking
                movement_indicator = cls._check_movement_patterns(activity_measurements, medication)
                if movement_indicator:
                    indicators.append(movement_indicator)
                
                # Check heart rate patterns (some medications affect heart rate)
                hr_indicator = cls._check_heart_rate_patterns(activity_measurements, medication)
                if hr_indicator:
                    indicators.append(hr_indicator)
            
            # Check for direct confirmation via smartwatch interaction
            notification_responses = NotificationDelivery.objects.filter(
                user=integration.user,
                integration=integration,
                notification_type=NotificationDelivery.NotificationType.MEDICATION_REMINDER,
                sent_at__gte=start_time,
                sent_at__lte=end_time,
                user_response='taken'
            )
            
            if notification_responses.exists():
                indicators.append({
                    'type': 'direct_confirmation',
                    'confidence': 0.95,
                    'timestamp': notification_responses.first().response_time,
                    'source': 'smartwatch_interaction'
                })
        
        except Exception as e:
            logger.error(f"Error analyzing adherence patterns: {str(e)}")
        
        return indicators
    
    @classmethod
    def _check_movement_patterns(cls, measurements, medication) -> Dict[str, Any]:
        """Check for movement patterns consistent with taking medication."""
        # Look for brief activity spikes that might indicate getting medication
        step_measurements = measurements.filter(
            measurement_type=WearableMeasurement.MeasurementType.STEPS
        )
        
        if step_measurements.count() >= 2:
            # Check for increase in steps followed by decrease (getting up, then sitting back down)
            values = list(step_measurements.values_list('value', 'measured_at'))
            
            # Simple pattern detection
            for i in range(len(values) - 1):
                current_steps, current_time = values[i]
                next_steps, next_time = values[i + 1]
                
                # Look for step increase indicating movement
                if next_steps > current_steps + 10:  # Threshold for meaningful movement
                    return {
                        'type': 'movement_pattern',
                        'confidence': 0.6,
                        'timestamp': next_time,
                        'source': 'step_analysis',
                        'details': f'Movement detected: {current_steps} to {next_steps} steps'
                    }
        
        return None
    
    @classmethod
    def _check_heart_rate_patterns(cls, measurements, medication) -> Dict[str, Any]:
        """Check for heart rate patterns that might indicate medication effects."""
        hr_measurements = measurements.filter(
            measurement_type=WearableMeasurement.MeasurementType.HEART_RATE
        ).order_by('measured_at')
        
        if hr_measurements.count() >= 3:
            # Check for patterns that might indicate medication effects
            values = list(hr_measurements.values_list('value', 'measured_at'))
            
            # Look for heart rate changes that might indicate medication
            baseline = sum(v[0] for v in values[:2]) / 2
            later_values = values[2:]
            
            for value, timestamp in later_values:
                # Check for significant change (varies by medication type)
                change_threshold = 10  # BPM change
                if abs(value - baseline) > change_threshold:
                    return {
                        'type': 'heart_rate_pattern',
                        'confidence': 0.4,
                        'timestamp': timestamp,
                        'source': 'heart_rate_analysis',
                        'details': f'HR change: {baseline:.1f} to {value} BPM'
                    }
        
        return None
    
    @classmethod
    def _generate_adherence_report(cls, medication: Medication, indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive adherence report."""
        
        # Calculate overall confidence score
        if indicators:
            total_confidence = sum(indicator['confidence'] for indicator in indicators)
            max_confidence = max(indicator['confidence'] for indicator in indicators)
            avg_confidence = total_confidence / len(indicators)
        else:
            total_confidence = 0
            max_confidence = 0
            avg_confidence = 0
        
        # Determine adherence likelihood
        if max_confidence >= 0.8:
            adherence_status = 'likely_taken'
        elif max_confidence >= 0.5:
            adherence_status = 'possibly_taken'
        else:
            adherence_status = 'likely_missed'
        
        return {
            'success': True,
            'medication_id': medication.id,
            'medication_name': medication.name,
            'adherence_status': adherence_status,
            'confidence_score': max_confidence,
            'average_confidence': avg_confidence,
            'indicators_count': len(indicators),
            'indicators': indicators,
            'analysis_timestamp': timezone.now(),
            'rare_disease_medication': medication.for_rare_condition
        }
    
    @classmethod
    def _notify_pharmaceutical_companies(cls, user, medication: Medication, report: Dict[str, Any]):
        """Notify pharmaceutical companies about adherence data if consented."""
        try:
            # This would integrate with your pharmaceutical notification system
            from communication.tasks import send_adherence_data_to_pharmco
            
            send_adherence_data_to_pharmco.delay(
                user_id=user.id,
                medication_id=medication.id,
                adherence_report=report
            )
            
        except Exception as e:
            logger.error(f"Error notifying pharmaceutical companies: {str(e)}")

