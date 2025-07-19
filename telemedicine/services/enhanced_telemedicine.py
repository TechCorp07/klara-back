# telemedicine/services/enhanced_telemedicine.py
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from django.utils import timezone
from django.conf import settings
from django.db import transaction
import logging

from fhir.models import FHIREncounter
from healthcare.models import MedicalRecord, VitalSign
from wearables.models import WearableIntegration, WearableMeasurement
from wearables.services.notification_service import WearableNotificationService

logger = logging.getLogger(__name__)

class EnhancedTelemedicineService:
    """
    Advanced telemedicine service for rare disease patients.
    Integrates with your existing FHIREncounter model and wearable data.
    """
    
    @classmethod
    def schedule_intelligent_appointment(cls, patient_id: int, provider_id: int, appointment_data: Dict) -> Dict:
        """
        Schedule telemedicine appointment with intelligent preparation and reminders.
        Uses your existing FHIREncounter model.
        """
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            patient = User.objects.get(id=patient_id, role='patient')
            provider = User.objects.get(id=provider_id, role='provider')
            
            # Create FHIREncounter
            appointment_time = datetime.fromisoformat(appointment_data['start_time'])
            
            encounter = FHIREncounter.objects.create(
                patient=patient,
                status='planned',
                class_code='virtual',
                start=appointment_time,
                end=appointment_time + timedelta(minutes=appointment_data.get('duration', 30)),
                type_code=appointment_data.get('type_code', 'routine-consultation'),
                type_display=appointment_data.get('type_display', 'Routine Consultation'),
                priority=appointment_data.get('priority', 'routine'),
                is_telemedicine=True,
                telemedicine_platform=appointment_data.get('platform', 'zoom'),
                participants=[
                    {
                        "type": "patient",
                        "individual": {"reference": f"Patient/{patient.id}"},
                        "required": "required"
                    },
                    {
                        "type": "practitioner", 
                        "individual": {"reference": f"Practitioner/{provider.id}"},
                        "required": "required"
                    }
                ],
                reason_code=appointment_data.get('reason_code', ''),
                reason_display=appointment_data.get('reason_display', '')
            )
            
            # Generate secure meeting details
            meeting_details = cls._generate_meeting_details(encounter, appointment_data.get('platform', 'zoom'))
            encounter.video_url = meeting_details['join_url']
            encounter.meeting_id = meeting_details['meeting_id']
            encounter.password = meeting_details.get('password', '')
            encounter.save()
            
            # Set up intelligent pre-appointment preparation
            preparation_result = cls._setup_appointment_preparation(encounter, patient, provider)
            
            # Schedule automated reminders
            reminder_result = cls._schedule_appointment_reminders(encounter)
            
            return {
                'status': 'success',
                'encounter_id': encounter.id,
                'meeting_details': meeting_details,
                'preparation_tasks': preparation_result,
                'reminder_schedule': reminder_result,
                'appointment_summary': {
                    'patient_name': f"{patient.first_name} {patient.last_name}",
                    'provider_name': f"{provider.first_name} {provider.last_name}",
                    'scheduled_time': encounter.start.isoformat(),
                    'duration_minutes': (encounter.end - encounter.start).total_seconds() / 60,
                    'platform': encounter.telemedicine_platform
                }
            }
            
        except Exception as e:
            logger.error(f"Error scheduling telemedicine appointment: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    @classmethod
    def prepare_pre_visit_data_collection(cls, encounter_id: int) -> Dict:
        """
        Collect and prepare patient data before telemedicine visit.
        Integrates with wearable devices and vital signs.
        """
        try:
            encounter = FHIREncounter.objects.get(id=encounter_id)
            patient = encounter.patient
            
            # Collect recent wearable data
            wearable_data = cls._collect_recent_wearable_data(patient, days=7)
            
            # Collect recent vital signs
            recent_vitals = cls._collect_recent_vital_signs(patient, days=7)
            
            # Collect medication adherence data
            adherence_data = cls._collect_recent_adherence_data(patient, days=14)
            
            # Generate pre-visit summary
            pre_visit_summary = {
                'encounter_id': encounter_id,
                'patient_id': patient.id,
                'collection_date': timezone.now().isoformat(),
                'wearable_data_summary': wearable_data,
                'vital_signs_summary': recent_vitals,
                'medication_adherence': adherence_data,
                'health_trends': cls._analyze_health_trends(wearable_data, recent_vitals),
                'clinical_alerts': cls._generate_clinical_alerts(patient, wearable_data, recent_vitals)
            }
            
            # Save summary to encounter metadata
            encounter.metadata = encounter.metadata or {}
            encounter.metadata['pre_visit_summary'] = pre_visit_summary
            encounter.save()
            
            # Send summary to provider
            cls._send_pre_visit_summary_to_provider(encounter, pre_visit_summary)
            
            return {
                'status': 'success',
                'summary': pre_visit_summary,
                'message': 'Pre-visit data collection completed'
            }
            
        except Exception as e:
            logger.error(f"Error preparing pre-visit data: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    @classmethod
    def start_telemedicine_session(cls, encounter_id: int, participant_id: int) -> Dict:
        """
        Initialize telemedicine session with real-time monitoring capabilities.
        """
        try:
            encounter = FHIREncounter.objects.get(id=encounter_id)
            
            # Update encounter status
            encounter.status = 'in-progress'
            encounter.actual_start = timezone.now()
            encounter.save()
            
            # Initialize session monitoring
            session_data = {
                'session_id': str(uuid.uuid4()),
                'encounter_id': encounter_id,
                'start_time': timezone.now().isoformat(),
                'participants': [],
                'real_time_data': {
                    'wearable_monitoring': False,
                    'vital_signs_sharing': False,
                    'medication_status': {}
                }
            }
            
            # Check if patient has real-time monitoring devices
            if encounter.patient.id == participant_id:
                wearable_devices = WearableIntegration.objects.filter(
                    user=encounter.patient,
                    status=WearableIntegration.ConnectionStatus.CONNECTED,
                    real_time_monitoring=True
                )
                
                if wearable_devices.exists():
                    session_data['real_time_data']['wearable_monitoring'] = True
                    # Start real-time data collection
                    cls._start_real_time_monitoring(session_data['session_id'], wearable_devices)
            
            # Save session data
            encounter.metadata = encounter.metadata or {}
            encounter.metadata['active_session'] = session_data
            encounter.save()
            
            return {
                'status': 'success',
                'session_data': session_data,
                'meeting_url': encounter.video_url,
                'real_time_features': session_data['real_time_data']
            }
            
        except Exception as e:
            logger.error(f"Error starting telemedicine session: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    @classmethod
    def capture_session_vitals(cls, encounter_id: int, vitals_data: Dict) -> Dict:
        """
        Capture vital signs during telemedicine session.
        Integrates with your VitalSign model.
        """
        try:
            encounter = FHIREncounter.objects.get(id=encounter_id)
            patient = encounter.patient
            
            # Get or create medical record
            medical_record, _ = MedicalRecord.objects.get_or_create(
                patient=patient,
                defaults={'record_type': 'telemedicine_session'}
            )
            
            created_vitals = []
            
            for vital_type, measurement in vitals_data.items():
                vital_sign = VitalSign.objects.create(
                    medical_record=medical_record,
                    measurement_type=vital_type,
                    value=measurement['value'],
                    unit=measurement['unit'],
                    recorded_date=timezone.now().date(),
                    recorded_time=timezone.now().time(),
                    source='telemedicine_session',
                    metadata={
                        'encounter_id': encounter_id,
                        'session_captured': True,
                        'measurement_method': measurement.get('method', 'manual_entry')
                    }
                )
                created_vitals.append({
                    'id': vital_sign.id,
                    'type': vital_type,
                    'value': measurement['value'],
                    'unit': measurement['unit']
                })
            
            # Update encounter with vital signs reference
            encounter.metadata = encounter.metadata or {}
            encounter.metadata['session_vitals'] = [v['id'] for v in created_vitals]
            encounter.save()
            
            return {
                'status': 'success',
                'captured_vitals': created_vitals,
                'message': f'Captured {len(created_vitals)} vital sign measurements'
            }
            
        except Exception as e:
            logger.error(f"Error capturing session vitals: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    @classmethod
    def complete_telemedicine_session(cls, encounter_id: int, session_notes: Dict) -> Dict:
        """
        Complete telemedicine session and generate comprehensive summary.
        """
        try:
            encounter = FHIREncounter.objects.get(id=encounter_id)
            
            # Update encounter status and end time
            encounter.status = 'finished'
            encounter.end = timezone.now()
            encounter.save()
            
            # Generate session summary
            session_summary = cls._generate_session_summary(encounter, session_notes)
            
            # Send post-visit instructions and follow-up
            cls._send_post_visit_instructions(encounter, session_summary)
            
            # Schedule follow-up reminders if needed
            if session_notes.get('schedule_follow_up'):
                cls._schedule_follow_up_reminders(encounter, session_notes['follow_up_details'])
            
            # Update medication schedules if changed
            if session_notes.get('medication_changes'):
                cls._update_medication_schedules(encounter.patient, session_notes['medication_changes'])
            
            return {
                'status': 'success',
                'session_summary': session_summary,
                'encounter_id': encounter_id,
                'duration_minutes': (encounter.end - encounter.start).total_seconds() / 60
            }
            
        except Exception as e:
            logger.error(f"Error completing telemedicine session: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    @classmethod
    def get_provider_dashboard_data(cls, provider_id: int) -> Dict:
        """
        Get comprehensive dashboard data for healthcare providers.
        Shows upcoming appointments, patient summaries, and alerts.
        """
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            provider = User.objects.get(id=provider_id, role='provider')
            today = timezone.now().date()
            
            # Upcoming appointments
            upcoming_encounters = FHIREncounter.objects.filter(
                participants__individual__reference=f"Practitioner/{provider_id}",
                status='planned',
                start__date__gte=today
            ).order_by('start')[:10]
            
            # Today's appointments
            todays_encounters = upcoming_encounters.filter(start__date=today)
            
            # Patient alerts and prep data
            patient_alerts = []
            for encounter in todays_encounters:
                patient_alert = cls._get_patient_preparation_status(encounter)
                if patient_alert:
                    patient_alerts.append(patient_alert)
            
            # Recent completed sessions
            recent_sessions = FHIREncounter.objects.filter(
                participants__individual__reference=f"Practitioner/{provider_id}",
                status='finished',
                end__gte=timezone.now() - timedelta(days=7)
            ).order_by('-end')[:5]
            
            dashboard_data = {
                'provider_id': provider_id,
                'summary': {
                    'todays_appointments': todays_encounters.count(),
                    'upcoming_appointments': upcoming_encounters.count(),
                    'patient_alerts': len(patient_alerts),
                    'recent_sessions_week': recent_sessions.count()
                },
                'todays_schedule': [
                    {
                        'encounter_id': enc.id,
                        'patient_name': f"{enc.patient.first_name} {enc.patient.last_name}",
                        'start_time': enc.start.isoformat(),
                        'duration': (enc.end - enc.start).total_seconds() / 60,
                        'reason': enc.reason_display,
                        'platform': enc.telemedicine_platform,
                        'preparation_status': cls._get_appointment_preparation_status(enc)
                    }
                    for enc in todays_encounters
                ],
                'patient_alerts': patient_alerts,
                'recent_sessions': [
                    {
                        'encounter_id': enc.id,
                        'patient_name': f"{enc.patient.first_name} {enc.patient.last_name}",
                        'completed_at': enc.end.isoformat(),
                        'duration': (enc.end - enc.start).total_seconds() / 60,
                        'follow_up_needed': enc.metadata.get('follow_up_required', False)
                    }
                    for enc in recent_sessions
                ]
            }
            
            return {
                'status': 'success',
                'dashboard_data': dashboard_data
            }
            
        except Exception as e:
            logger.error(f"Error getting provider dashboard data: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    # Helper methods
    @classmethod
    def _generate_meeting_details(cls, encounter: FHIREncounter, platform: str) -> Dict:
        """Generate secure meeting details for various platforms."""
        meeting_id = str(uuid.uuid4())[:12]
        
        platform_configs = {
            'zoom': {
                'join_url': f"https://zoom.us/j/{meeting_id}",
                'meeting_id': meeting_id,
                'password': str(uuid.uuid4())[:8]
            },
            'teams': {
                'join_url': f"https://teams.microsoft.com/l/meetup-join/{meeting_id}",
                'meeting_id': meeting_id
            },
            'webex': {
                'join_url': f"https://webex.com/meet/{meeting_id}",
                'meeting_id': meeting_id,
                'password': str(uuid.uuid4())[:8]
            },
            'custom': {
                'join_url': f"https://yourhealthsystem.com/telemedicine/join/{meeting_id}",
                'meeting_id': meeting_id,
                'password': str(uuid.uuid4())[:12]
            }
        }
        
        return platform_configs.get(platform, platform_configs['custom'])
    
    @classmethod
    def _setup_appointment_preparation(cls, encounter: FHIREncounter, patient, provider) -> Dict:
        """Set up intelligent appointment preparation tasks."""
        preparation_tasks = {
            'pre_visit_data_collection': {
                'status': 'scheduled',
                'due_date': encounter.start - timedelta(hours=24),
                'description': 'Collect recent health data and medication adherence'
            },
            'wearable_data_sync': {
                'status': 'pending',
                'description': 'Sync latest wearable device measurements'
            },
            'medication_review': {
                'status': 'pending', 
                'description': 'Review current medications and adherence'
            }
        }
        
        # Schedule data collection 24 hours before appointment
        collection_time = encounter.start - timedelta(hours=24)
        
        return preparation_tasks
    
    @classmethod
    def _collect_recent_wearable_data(cls, patient, days: int = 7) -> Dict:
        """Collect recent wearable data for patient."""
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        measurements = WearableMeasurement.objects.filter(
            user=patient,
            measured_at__gte=start_date
        ).order_by('-measured_at')
        
        summary = {
            'total_measurements': measurements.count(),
            'measurement_types': list(measurements.values_list('measurement_type', flat=True).distinct()),
            'latest_sync': measurements.first().measured_at.isoformat() if measurements.exists() else None,
            'key_metrics': {}
        }
        
        # Calculate averages for key metrics
        for measurement_type in summary['measurement_types']:
            type_measurements = measurements.filter(measurement_type=measurement_type)
            if type_measurements.exists():
                avg_value = sum(m.value for m in type_measurements) / type_measurements.count()
                summary['key_metrics'][measurement_type] = {
                    'average': round(avg_value, 2),
                    'count': type_measurements.count(),
                    'unit': type_measurements.first().unit
                }
        
        return summary
    
    @classmethod
    def _collect_recent_vital_signs(cls, patient, days: int = 7) -> Dict:
        """Collect recent vital signs for patient."""
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=days)
        
        vitals = VitalSign.objects.filter(
            medical_record__patient=patient,
            recorded_date__gte=start_date
        ).order_by('-recorded_date')
        
        return {
            'total_vitals': vitals.count(),
            'latest_reading': vitals.first().recorded_date.isoformat() if vitals.exists() else None,
            'vital_types': list(vitals.values_list('measurement_type', flat=True).distinct())
        }
    
    @classmethod
    def _collect_recent_adherence_data(cls, patient, days: int = 14) -> Dict:
        """Collect recent medication adherence data."""
        from medication.models import AdherenceRecord
        
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=days)
        
        adherence_records = AdherenceRecord.objects.filter(
            patient=patient,
            period_start__gte=start_date
        )
        
        if not adherence_records.exists():
            return {'status': 'no_data'}
        
        avg_adherence = sum(r.adherence_rate for r in adherence_records) / adherence_records.count()
        
        return {
            'average_adherence': round(avg_adherence, 1),
            'total_medications': adherence_records.count(),
            'period_days': days
        }
    
    @classmethod
    def _analyze_health_trends(cls, wearable_data: Dict, vitals_data: Dict) -> Dict:
        """Analyze health trends from collected data."""
        trends = {
            'overall_status': 'stable',
            'concerns': [],
            'improvements': []
        }
        
        # Simple trend analysis - could be enhanced with ML
        if wearable_data.get('total_measurements', 0) < 5:
            trends['concerns'].append('Low wearable device usage')
        
        if vitals_data.get('total_vitals', 0) == 0:
            trends['concerns'].append('No recent vital signs recorded')
        
        return trends
    
    @classmethod
    def _generate_clinical_alerts(cls, patient, wearable_data: Dict, vitals_data: Dict) -> List[Dict]:
        """Generate clinical alerts based on data analysis."""
        alerts = []
        
        # Check for data gaps
        if wearable_data.get('total_measurements', 0) == 0:
            alerts.append({
                'type': 'data_gap',
                'severity': 'medium',
                'message': 'No wearable data available for the past week'
            })
        
        # Add more sophisticated alert logic here
        
        return alerts