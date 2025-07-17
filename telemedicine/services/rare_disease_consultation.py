# telemedicine/services/rare_disease_consultation.py
from django.utils import timezone
from django.db import transaction
from datetime import timedelta, datetime
from typing import Dict, List, Any, Optional
import logging

from ..models import Appointment, Consultation
from healthcare.models import VitalSign, Condition, Symptom
from medication.models import Medication, AdherenceRecord
from wearables.models import WearableMeasurement
from users.models import User

logger = logging.getLogger(__name__)

class RareDiseaseConsultationService:
    """
    Service for managing rare disease consultations with specialized workflows.
    Integrates medication adherence, wearable data, and family member participation.
    """
    
    @classmethod
    def prepare_rare_disease_consultation(cls, appointment: Appointment) -> Dict[str, Any]:
        """
        Prepare comprehensive data for rare disease consultation.
        Gathers vitals, medication adherence, symptoms, and wearable data.
        """
        try:
            patient = appointment.patient
            
            # Check if patient has rare conditions
            has_rare_condition = patient.medical_records.filter(
                conditions__is_rare_condition=True,
                conditions__status='active'
            ).exists()
            
            if not has_rare_condition:
                return {
                    'rare_condition': False,
                    'message': 'Standard consultation preparation'
                }
            
            # Gather comprehensive pre-consultation data
            consultation_data = {
                'rare_condition': True,
                'patient_summary': cls._get_patient_summary(patient),
                'medication_adherence': cls._get_recent_adherence_data(patient),
                'symptom_tracking': cls._get_recent_symptoms(patient),
                'vitals_summary': cls._get_recent_vitals(patient),
                'wearable_insights': cls._get_wearable_insights(patient),
                'family_concerns': cls._get_family_concerns(patient),
                'care_alerts': cls._get_care_alerts(patient, appointment),
                'research_participation': cls._check_research_participation(patient)
            }
            
            # Generate consultation checklist
            consultation_data['consultation_checklist'] = cls._generate_consultation_checklist(
                patient, appointment, consultation_data
            )
            
            return consultation_data
            
        except Exception as e:
            logger.error(f"Error preparing rare disease consultation: {str(e)}")
            return {'error': str(e)}
    
    @classmethod
    def create_rare_disease_consultation_plan(cls, consultation: Consultation, 
                                            consultation_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create specialized consultation plan for rare disease patients.
        Includes medication reviews, symptom assessments, and care coordination.
        """
        try:
            patient = consultation.patient
            
            # Create structured consultation plan
            consultation_plan = {
                'patient_id': str(patient.id),
                'consultation_id': str(consultation.id),
                'consultation_type': 'rare_disease_focused',
                'duration_recommended': cls._calculate_recommended_duration(consultation_data),
                'agenda': cls._create_consultation_agenda(consultation_data),
                'medication_review': cls._create_medication_review_plan(patient, consultation_data),
                'symptom_assessment': cls._create_symptom_assessment_plan(consultation_data),
                'family_involvement': cls._assess_family_involvement_needs(patient),
                'follow_up_plan': cls._create_follow_up_plan(patient, consultation_data),
                'research_opportunities': cls._identify_research_opportunities(patient)
            }
            
            # Store plan in consultation
            consultation.platform_data.update({
                'rare_disease_plan': consultation_plan,
                'preparation_completed': True,
                'plan_created_at': timezone.now().isoformat()
            })
            consultation.save(update_fields=['platform_data'])
            
            return consultation_plan
            
        except Exception as e:
            logger.error(f"Error creating consultation plan: {str(e)}")
            return {'error': str(e)}
    
    @classmethod
    def notify_care_team(cls, consultation: Consultation, notification_type: str = 'scheduled') -> bool:
        """
        Notify care team about rare disease consultation.
        Includes providers, caregivers, and family members as appropriate.
        """
        try:
            patient = consultation.patient
            
            # Get authorized care team members
            care_team = []
            
            # Add authorized caregivers
            if hasattr(patient, 'patient_profile'):
                authorized_caregivers = patient.patient_profile.caregiver_authorizations.filter(
                    access_level__in=['FULL', 'SCHEDULE']
                )
                
                for auth in authorized_caregivers:
                    care_team.append({
                        'user': auth.caregiver,
                        'role': 'caregiver',
                        'access_level': auth.access_level
                    })
            
            # Add primary physician if different from consultation provider
            medical_record = patient.medical_records.first()
            if medical_record and medical_record.primary_physician != consultation.provider:
                care_team.append({
                    'user': medical_record.primary_physician,
                    'role': 'primary_physician',
                    'access_level': 'FULL'
                })
            
            # Send notifications
            from communication.tasks import send_care_team_notification
            
            notification_data = {
                'consultation_id': str(consultation.id),
                'patient_name': patient.get_full_name(),
                'provider_name': consultation.provider.get_full_name(),
                'scheduled_time': consultation.appointment.scheduled_time.isoformat(),
                'consultation_type': consultation.appointment.appointment_type,
                'notification_type': notification_type
            }
            
            for member in care_team:
                send_care_team_notification.delay(
                    recipient_id=member['user'].id,
                    notification_data=notification_data,
                    member_role=member['role']
                )
            
            return True
            
        except Exception as e:
            logger.error(f"Error notifying care team: {str(e)}")
            return False
    
    @classmethod
    def collect_pre_consultation_vitals(cls, patient: User, consultation: Consultation) -> Dict[str, Any]:
        """
        Collect and prepare vital signs for rare disease consultation.
        Integrates wearable data and manual entries.
        """
        try:
            # Get recent vitals (last 7 days)
            recent_vitals = VitalSign.objects.filter(
                medical_record__patient=patient,
                measured_at__gte=timezone.now() - timedelta(days=7)
            ).order_by('-measured_at')
            
            # Get wearable data (last 24 hours)
            recent_wearable = WearableMeasurement.objects.filter(
                user=patient,
                measured_at__gte=timezone.now() - timedelta(hours=24)
            ).order_by('-measured_at')
            
            # Organize vitals by type
            vitals_summary = {}
            
            # Process manual vitals
            for vital in recent_vitals:
                if vital.measurement_type not in vitals_summary:
                    vitals_summary[vital.measurement_type] = []
                
                vitals_summary[vital.measurement_type].append({
                    'value': vital.value,
                    'unit': vital.unit,
                    'measured_at': vital.measured_at.isoformat(),
                    'source': vital.source,
                    'is_abnormal': vital.is_abnormal
                })
            
            # Process wearable data
            wearable_summary = {}
            for measurement in recent_wearable:
                if measurement.measurement_type not in wearable_summary:
                    wearable_summary[measurement.measurement_type] = []
                
                wearable_summary[measurement.measurement_type].append({
                    'value': measurement.value,
                    'unit': measurement.unit,
                    'measured_at': measurement.measured_at.isoformat(),
                    'source': 'wearable',
                    'device_type': measurement.integration_type
                })
            
            # Generate vitals checklist for consultation
            vitals_checklist = cls._generate_vitals_checklist(patient, vitals_summary, wearable_summary)
            
            return {
                'manual_vitals': vitals_summary,
                'wearable_data': wearable_summary,
                'vitals_checklist': vitals_checklist,
                'last_updated': timezone.now().isoformat(),
                'recommendations': cls._get_vitals_recommendations(vitals_summary, wearable_summary)
            }
            
        except Exception as e:
            logger.error(f"Error collecting pre-consultation vitals: {str(e)}")
            return {'error': str(e)}
    
    @classmethod
    def create_post_consultation_plan(cls, consultation: Consultation, 
                                    consultation_notes: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create comprehensive post-consultation care plan for rare disease patients.
        """
        try:
            patient = consultation.patient
            
            # Extract key information from consultation notes
            diagnosis_updates = consultation_notes.get('diagnosis_updates', [])
            medication_changes = consultation_notes.get('medication_changes', [])
            symptom_concerns = consultation_notes.get('symptom_concerns', [])
            follow_up_needs = consultation_notes.get('follow_up_needs', {})
            
            # Create care plan
            care_plan = {
                'consultation_id': str(consultation.id),
                'patient_id': str(patient.id),
                'created_at': timezone.now().isoformat(),
                'medication_plan': cls._create_medication_plan(medication_changes, patient),
                'monitoring_plan': cls._create_monitoring_plan(patient, consultation_notes),
                'symptom_tracking': cls._create_symptom_tracking_plan(symptom_concerns),
                'appointment_schedule': cls._create_appointment_schedule(follow_up_needs),
                'caregiver_instructions': cls._create_caregiver_instructions(consultation_notes),
                'family_communication': cls._create_family_communication_plan(patient, consultation_notes),
                'research_updates': cls._check_research_updates(patient, consultation_notes)
            }
            
            # Store care plan
            consultation.treatment_plan = care_plan
            consultation.save(update_fields=['treatment_plan'])
            
            # Send care plan to relevant parties
            cls._distribute_care_plan(consultation, care_plan)
            
            return care_plan
            
        except Exception as e:
            logger.error(f"Error creating post-consultation plan: {str(e)}")
            return {'error': str(e)}
    
    @classmethod
    def _get_patient_summary(cls, patient: User) -> Dict[str, Any]:
        """Get comprehensive patient summary for rare disease consultation."""
        
        # Get active rare conditions
        rare_conditions = Condition.objects.filter(
            medical_record__patient=patient,
            is_rare_condition=True,
            status='active'
        ).select_related('rare_condition')
        
        # Get recent medications
        active_medications = Medication.objects.filter(
            patient=patient,
            active=True
        )
        
        return {
            'rare_conditions': [
                {
                    'name': condition.name,
                    'diagnosed_date': condition.diagnosed_date.isoformat() if condition.diagnosed_date else None,
                    'biomarker_status': condition.biomarker_status,
                    'last_assessment': condition.last_assessment_date.isoformat() if condition.last_assessment_date else None
                }
                for condition in rare_conditions
            ],
            'total_medications': active_medications.count(),
            'rare_disease_medications': active_medications.filter(for_rare_condition=True).count(),
            'orphan_drugs': active_medications.filter(orphan_drug=True).count(),
            'protocol_participation': patient.patient_profile.protocol_adherence_monitoring if hasattr(patient, 'patient_profile') else False
        }
    
    @classmethod
    def _get_recent_adherence_data(cls, patient: User, days: int = 14) -> Dict[str, Any]:
        """Get recent medication adherence data."""
        
        # Get adherence records for last 14 days
        adherence_records = AdherenceRecord.objects.filter(
            patient=patient,
            period_end__gte=timezone.now().date() - timedelta(days=days)
        ).select_related('medication')
        
        # Calculate overall adherence
        if adherence_records.exists():
            avg_adherence = sum(record.adherence_rate for record in adherence_records) / len(adherence_records)
            
            # Get medication-specific adherence
            medication_adherence = []
            for record in adherence_records:
                medication_adherence.append({
                    'medication': record.medication.name,
                    'adherence_rate': record.adherence_rate,
                    'doses_missed': record.doses_missed,
                    'period_end': record.period_end.isoformat(),
                    'rare_condition_med': record.medication.for_rare_condition
                })
            
            # Identify concerning patterns
            concerning_medications = [
                med for med in medication_adherence 
                if med['adherence_rate'] < 80 and med['rare_condition_med']
            ]
            
            return {
                'average_adherence': round(avg_adherence, 1),
                'medication_adherence': medication_adherence,
                'concerning_medications': concerning_medications,
                'total_medications_tracked': len(set(record.medication.name for record in adherence_records))
            }
        
        return {
            'average_adherence': None,
            'message': 'No recent adherence data available'
        }
    
    @classmethod
    def _generate_consultation_checklist(cls, patient: User, appointment: Appointment, 
                                       consultation_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate consultation checklist for provider."""
        
        checklist = []
        
        # Medication adherence review
        adherence_data = consultation_data.get('medication_adherence', {})
        if adherence_data.get('concerning_medications'):
            checklist.append({
                'category': 'medication',
                'priority': 'high',
                'item': 'Review medication adherence concerns',
                'details': f"{len(adherence_data['concerning_medications'])} medications with <80% adherence",
                'action_required': True
            })
        
        # Symptom assessment
        symptoms = consultation_data.get('symptom_tracking', {})
        if symptoms.get('severe_symptoms'):
            checklist.append({
                'category': 'symptoms',
                'priority': 'high',
                'item': 'Assess severe symptoms',
                'details': f"{len(symptoms['severe_symptoms'])} severe symptoms reported",
                'action_required': True
            })
        
        # Vitals review
        vitals = consultation_data.get('vitals_summary', {})
        if vitals.get('abnormal_readings'):
            checklist.append({
                'category': 'vitals',
                'priority': 'medium',
                'item': 'Review abnormal vital signs',
                'details': f"{vitals['abnormal_readings']} abnormal readings",
                'action_required': True
            })
        
        # Family concerns
        family_concerns = consultation_data.get('family_concerns', {})
        if family_concerns.get('has_concerns'):
            checklist.append({
                'category': 'family',
                'priority': 'medium',
                'item': 'Address family concerns',
                'details': family_concerns.get('summary', ''),
                'action_required': True
            })
        
        # Research participation
        research = consultation_data.get('research_participation', {})
        if research.get('eligible_studies'):
            checklist.append({
                'category': 'research',
                'priority': 'low',
                'item': 'Discuss research opportunities',
                'details': f"{len(research['eligible_studies'])} eligible studies",
                'action_required': False
            })
        
        return sorted(checklist, key=lambda x: {'high': 3, 'medium': 2, 'low': 1}[x['priority']], reverse=True)
