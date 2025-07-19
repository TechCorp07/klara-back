# research/services/clinical_trials_service.py
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from django.utils import timezone
from django.db.models import Q, Count, Avg
from django.conf import settings
import logging

from users.models import ConsentRecord, ResearcherProfile
from healthcare.models import HealthDataConsent, Condition, MedicalRecord
from medication.models import Medication, AdherenceRecord, SideEffect
from wearables.models import WearableMeasurement

logger = logging.getLogger(__name__)

class ResearchClinicalTrialsService:
    """
    Advanced research and clinical trials management service.
    Integrates with your existing consent, patient, and healthcare data models.
    """
    
    @classmethod
    def create_research_study(cls, researcher_id: int, study_data: Dict) -> Dict:
        """
        Create new research study with proper consent management.
        Uses your existing ConsentRecord and ResearcherProfile models.
        """
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            researcher = User.objects.get(id=researcher_id, role='researcher')
            researcher_profile = researcher.researcher_profile
            
            # Validate researcher credentials
            if not researcher_profile.is_verified:
                return {
                    'status': 'error',
                    'message': 'Researcher profile must be verified before creating studies'
                }
            
            # Create study record
            study = {
                'study_id': f"STUDY_{timezone.now().strftime('%Y%m%d')}_{researcher_id}",
                'title': study_data['title'],
                'description': study_data['description'],
                'principal_investigator': {
                    'researcher_id': researcher_id,
                    'name': f"{researcher.first_name} {researcher.last_name}",
                    'institution': researcher_profile.institution_name,
                    'credentials': researcher_profile.research_areas
                },
                'study_type': study_data.get('study_type', 'observational'),
                'target_conditions': study_data.get('target_conditions', []),
                'inclusion_criteria': study_data.get('inclusion_criteria', {}),
                'exclusion_criteria': study_data.get('exclusion_criteria', {}),
                'data_requirements': study_data.get('data_requirements', []),
                'estimated_duration': study_data.get('duration_months', 12),
                'max_participants': study_data.get('max_participants', 100),
                'irb_approval': study_data.get('irb_approval_number', ''),
                'consent_template': cls._generate_consent_template(study_data),
                'created_at': timezone.now().isoformat(),
                'status': 'pending_approval',
                'participants': [],
                'data_collection_schedule': study_data.get('collection_schedule', 'monthly')
            }
            
            # Save study to researcher's profile metadata
            researcher_profile.active_studies = researcher_profile.active_studies or []
            researcher_profile.active_studies.append(study)
            researcher_profile.save()
            
            # Find eligible patients
            eligible_patients = cls._find_eligible_patients(study)
            
            return {
                'status': 'success',
                'study_id': study['study_id'],
                'study_details': study,
                'eligible_patients_count': len(eligible_patients),
                'next_steps': [
                    'Submit for institutional review',
                    'Obtain necessary approvals',
                    'Begin patient recruitment'
                ]
            }
            
        except Exception as e:
            logger.error(f"Error creating research study: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    @classmethod
    def invite_patient_to_study(cls, study_id: str, patient_id: int, researcher_id: int) -> Dict:
        """
        Invite patient to participate in research study with proper consent workflow.
        """
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            patient = User.objects.get(id=patient_id, role='patient')
            researcher = User.objects.get(id=researcher_id, role='researcher')
            
            # Get study details
            study = cls._get_study_by_id(study_id, researcher_id)
            if not study:
                return {'status': 'error', 'message': 'Study not found'}
            
            # Check eligibility
            eligibility_result = cls._check_patient_eligibility(patient, study)
            if not eligibility_result['eligible']:
                return {
                    'status': 'error',
                    'message': 'Patient does not meet study criteria',
                    'reasons': eligibility_result['reasons']
                }
            
            # Create consent record
            consent_record = ConsentRecord.objects.create(
                patient=patient,
                researcher=researcher,
                consent_type='research_study',
                study_id=study_id,
                study_title=study['title'],
                consent_details={
                    'study_description': study['description'],
                    'data_requirements': study['data_requirements'],
                    'duration_months': study['estimated_duration'],
                    'consent_template': study['consent_template']
                },
                status='pending',
                consent_date=timezone.now(),
                expiry_date=timezone.now() + timedelta(days=study['estimated_duration'] * 30)
            )
            
            # Send invitation notification
            invitation_sent = cls._send_study_invitation(patient, study, consent_record)
            
            return {
                'status': 'success',
                'consent_record_id': consent_record.id,
                'invitation_sent': invitation_sent,
                'patient_id': patient_id,
                'study_id': study_id,
                'message': 'Study invitation sent to patient'
            }
            
        except Exception as e:
            logger.error(f"Error inviting patient to study: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    @classmethod
    def patient_consent_to_study(cls, consent_record_id: int, patient_response: Dict) -> Dict:
        """
        Process patient consent response for research study participation.
        """
        try:
            consent_record = ConsentRecord.objects.get(id=consent_record_id)
            
            if patient_response.get('consented', False):
                # Patient consented
                consent_record.status = 'granted'
                consent_record.consent_given_at = timezone.now()
                consent_record.save()
                
                # Add patient to study
                cls._add_patient_to_study(consent_record)
                
                # Set up data collection schedule
                collection_schedule = cls._setup_data_collection_schedule(consent_record)
                
                # Create health data consent entries
                cls._create_health_data_consents(consent_record, patient_response.get('data_permissions', {}))
                
                return {
                    'status': 'success',
                    'message': 'Successfully enrolled in research study',
                    'study_id': consent_record.study_id,
                    'collection_schedule': collection_schedule,
                    'next_steps': [
                        'Complete baseline data collection',
                        'Sync wearable devices if applicable',
                        'Attend initial study visit'
                    ]
                }
            else:
                # Patient declined
                consent_record.status = 'declined'
                consent_record.save()
                
                return {
                    'status': 'success',
                    'message': 'Study participation declined',
                    'study_id': consent_record.study_id
                }
                
        except Exception as e:
            logger.error(f"Error processing patient consent: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    @classmethod
    def collect_research_data(cls, study_id: str, patient_id: int, collection_type: str = 'routine') -> Dict:
        """
        Collect and aggregate research data for a study participant.
        Uses your existing health data models.
        """
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            patient = User.objects.get(id=patient_id, role='patient')
            
            # Verify patient is enrolled in study
            consent_record = ConsentRecord.objects.filter(
                patient=patient,
                study_id=study_id,
                status='granted'
            ).first()
            
            if not consent_record:
                return {'status': 'error', 'message': 'Patient not enrolled in study'}
            
            # Get study details
            study = cls._get_study_by_consent_record(consent_record)
            
            # Collect data based on study requirements
            research_data = {
                'study_id': study_id,
                'patient_id': patient_id,
                'collection_date': timezone.now().isoformat(),
                'collection_type': collection_type,
                'data_points': {}
            }
            
            # Collect medication adherence data
            if 'medication_adherence' in study['data_requirements']:
                adherence_data = cls._collect_medication_adherence_data(patient)
                research_data['data_points']['medication_adherence'] = adherence_data
            
            # Collect wearable device data
            if 'wearable_data' in study['data_requirements']:
                wearable_data = cls._collect_wearable_research_data(patient)
                research_data['data_points']['wearable_data'] = wearable_data
            
            # Collect side effects and adverse events
            if 'adverse_events' in study['data_requirements']:
                adverse_events = cls._collect_adverse_events_data(patient)
                research_data['data_points']['adverse_events'] = adverse_events
            
            # Collect condition progression data
            if 'condition_progression' in study['data_requirements']:
                progression_data = cls._collect_condition_progression_data(patient, study['target_conditions'])
                research_data['data_points']['condition_progression'] = progression_data
            
            # Collect quality of life indicators
            if 'quality_of_life' in study['data_requirements']:
                qol_data = cls._collect_quality_of_life_data(patient)
                research_data['data_points']['quality_of_life'] = qol_data
            
            # Store in consent record metadata for research access
            consent_record.research_data = consent_record.research_data or []
            consent_record.research_data.append(research_data)
            consent_record.save()
            
            return {
                'status': 'success',
                'research_data': research_data,
                'data_points_collected': len(research_data['data_points']),
                'next_collection': cls._calculate_next_collection_date(consent_record, study)
            }
            
        except Exception as e:
            logger.error(f"Error collecting research data: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    @classmethod
    def generate_research_analytics(cls, study_id: str, researcher_id: int, analytics_type: str = 'comprehensive') -> Dict:
        """
        Generate analytics and insights for research study.
        Provides anonymized aggregate data for researchers.
        """
        try:
            # Get study details
            study = cls._get_study_by_id(study_id, researcher_id)
            if not study:
                return {'status': 'error', 'message': 'Study not found'}
            
            # Get all consent records for this study
            consent_records = ConsentRecord.objects.filter(
                study_id=study_id,
                status='granted'
            )
            
            if not consent_records.exists():
                return {'status': 'error', 'message': 'No participants found for study'}
            
            analytics = {
                'study_id': study_id,
                'generated_at': timezone.now().isoformat(),
                'analytics_type': analytics_type,
                'participant_summary': {
                    'total_enrolled': consent_records.count(),
                    'active_participants': consent_records.filter(status='granted').count(),
                    'data_collections_completed': sum(
                        len(cr.research_data or []) for cr in consent_records
                    )
                },
                'data_insights': {}
            }
            
            # Analyze medication adherence trends
            if 'medication_adherence' in study['data_requirements']:
                adherence_analytics = cls._analyze_medication_adherence_trends(consent_records)
                analytics['data_insights']['medication_adherence'] = adherence_analytics
            
            # Analyze adverse events
            if 'adverse_events' in study['data_requirements']:
                adverse_events_analytics = cls._analyze_adverse_events_patterns(consent_records)
                analytics['data_insights']['adverse_events'] = adverse_events_analytics
            
            # Analyze wearable data trends
            if 'wearable_data' in study['data_requirements']:
                wearable_analytics = cls._analyze_wearable_data_trends(consent_records)
                analytics['data_insights']['wearable_data'] = wearable_analytics
            
            # Analyze condition progression
            if 'condition_progression' in study['data_requirements']:
                progression_analytics = cls._analyze_condition_progression(consent_records, study['target_conditions'])
                analytics['data_insights']['condition_progression'] = progression_analytics
            
            return {
                'status': 'success',
                'analytics': analytics,
                'export_options': [
                    'csv_export',
                    'statistical_package',
                    'fhir_bundle',
                    'research_database'
                ]
            }
            
        except Exception as e:
            logger.error(f"Error generating research analytics: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    @classmethod
    def get_patient_research_dashboard(cls, patient_id: int) -> Dict:
        """
        Get research participation dashboard for patients.
        Shows current studies, contribution data, and opportunities.
        """
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            patient = User.objects.get(id=patient_id, role='patient')
            
            # Get current research participations
            active_studies = ConsentRecord.objects.filter(
                patient=patient,
                status='granted'
            )
            
            # Get available studies for patient
            available_studies = cls._find_available_studies_for_patient(patient)
            
            # Calculate contribution metrics
            contribution_metrics = cls._calculate_patient_contribution_metrics(patient, active_studies)
            
            dashboard_data = {
                'patient_id': patient_id,
                'current_studies': [
                    {
                        'study_id': study.study_id,
                        'study_title': study.study_title,
                        'enrollment_date': study.consent_given_at.isoformat() if study.consent_given_at else None,
                        'data_contributions': len(study.research_data or []),
                        'next_collection': cls._get_next_collection_date(study),
                        'contribution_status': 'active',
                        'researcher_institution': study.researcher.researcher_profile.institution_name if hasattr(study.researcher, 'researcher_profile') else 'Unknown'
                    }
                    for study in active_studies
                ],
                'available_opportunities': [
                    {
                        'study_id': study['study_id'],
                        'title': study['title'],
                        'description': study['description'][:200] + '...',
                        'estimated_duration': study['estimated_duration'],
                        'eligibility_match': study.get('eligibility_score', 0),
                        'institution': study['principal_investigator']['institution']
                    }
                    for study in available_studies[:5]  # Show top 5 matches
                ],
                'contribution_metrics': contribution_metrics,
                'research_impact': cls._calculate_research_impact(patient, active_studies)
            }
            
            return {
                'status': 'success',
                'dashboard_data': dashboard_data
            }
            
        except Exception as e:
            logger.error(f"Error getting patient research dashboard: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    # Helper methods
    @classmethod
    def _generate_consent_template(cls, study_data: Dict) -> Dict:
        """Generate standardized consent template for research study."""
        return {
            'sections': [
                {
                    'title': 'Study Purpose',
                    'content': study_data.get('description', ''),
                    'required': True
                },
                {
                    'title': 'Data Collection',
                    'content': f"This study will collect: {', '.join(study_data.get('data_requirements', []))}",
                    'required': True
                },
                {
                    'title': 'Duration',
                    'content': f"Participation is expected to last {study_data.get('duration_months', 12)} months",
                    'required': True
                },
                {
                    'title': 'Risks and Benefits',
                    'content': study_data.get('risks_benefits', 'Standard research risks apply'),
                    'required': True
                },
                {
                    'title': 'Data Privacy',
                    'content': 'Your data will be anonymized and used only for research purposes',
                    'required': True
                }
            ],
            'consent_checkboxes': [
                'I understand the purpose of this study',
                'I consent to data collection as described',
                'I understand I can withdraw at any time',
                'I consent to sharing anonymized data for research'
            ]
        }
    
    @classmethod
    def _find_eligible_patients(cls, study: Dict) -> List[int]:
        """Find patients eligible for research study based on criteria."""
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        # Start with all patients who have research consent
        eligible_patients = User.objects.filter(
            role='patient',
            patient_profile__research_participation_consent=True
        )
        
        # Filter by target conditions
        if study.get('target_conditions'):
            condition_codes = study['target_conditions']
            eligible_patients = eligible_patients.filter(
                medical_records__conditions__code__in=condition_codes
            )
        
        # Apply inclusion criteria
        inclusion_criteria = study.get('inclusion_criteria', {})
        
        if inclusion_criteria.get('min_age'):
            # Filter by age (would need to calculate from date_of_birth)
            pass
        
        if inclusion_criteria.get('medications'):
            # Filter by specific medications
            required_meds = inclusion_criteria['medications']
            eligible_patients = eligible_patients.filter(
                medications__name__in=required_meds,
                medications__active=True
            )
        
        # Apply exclusion criteria
        exclusion_criteria = study.get('exclusion_criteria', {})
        
        if exclusion_criteria.get('conditions'):
            excluded_conditions = exclusion_criteria['conditions']
            eligible_patients = eligible_patients.exclude(
                medical_records__conditions__code__in=excluded_conditions
            )
        
        return list(eligible_patients.values_list('id', flat=True).distinct())
    
    @classmethod
    def _collect_medication_adherence_data(cls, patient) -> Dict:
        """Collect medication adherence data for research."""
        adherence_records = AdherenceRecord.objects.filter(
            patient=patient,
            period_start__gte=timezone.now().date() - timedelta(days=30)
        )
        
        if not adherence_records.exists():
            return {'status': 'no_data'}
        
        return {
            'average_adherence': adherence_records.aggregate(avg=Avg('adherence_rate'))['avg'],
            'total_medications': adherence_records.count(),
            'adherence_trend': 'stable',  # Could be calculated from historical data
            'data_points': adherence_records.count()
        }
    
    @classmethod
    def _collect_wearable_research_data(cls, patient) -> Dict:
        """Collect wearable device data for research."""
        measurements = WearableMeasurement.objects.filter(
            user=patient,
            measured_at__gte=timezone.now() - timedelta(days=30)
        )
        
        if not measurements.exists():
            return {'status': 'no_data'}
        
        # Aggregate by measurement type
        measurement_summary = {}
        for measurement_type in measurements.values_list('measurement_type', flat=True).distinct():
            type_measurements = measurements.filter(measurement_type=measurement_type)
            measurement_summary[measurement_type] = {
                'count': type_measurements.count(),
                'average': type_measurements.aggregate(avg=Avg('value'))['avg'],
                'unit': type_measurements.first().unit
            }
        
        return {
            'total_measurements': measurements.count(),
            'measurement_types': measurement_summary,
            'collection_period_days': 30
        }
    
    @classmethod
    def _collect_adverse_events_data(cls, patient) -> Dict:
        """Collect adverse events and side effects data."""
        side_effects = SideEffect.objects.filter(
            patient=patient,
            reported_date__gte=timezone.now().date() - timedelta(days=30)
        )
        
        return {
            'total_events': side_effects.count(),
            'severity_distribution': dict(side_effects.values_list('severity').annotate(count=Count('id'))),
            'most_common_effects': list(side_effects.values('description').annotate(count=Count('id')).order_by('-count')[:5])
        }
    
    @classmethod
    def _analyze_medication_adherence_trends(cls, consent_records) -> Dict:
        """Analyze medication adherence trends across study participants."""
        all_adherence_data = []
        
        for consent_record in consent_records:
            if consent_record.research_data:
                for data_point in consent_record.research_data:
                    adherence_data = data_point.get('data_points', {}).get('medication_adherence')
                    if adherence_data and adherence_data.get('average_adherence'):
                        all_adherence_data.append(adherence_data['average_adherence'])
        
        if not all_adherence_data:
            return {'status': 'no_data'}
        
        return {
            'participant_count': len(all_adherence_data),
            'mean_adherence': sum(all_adherence_data) / len(all_adherence_data),
            'adherence_distribution': {
                'excellent_80_plus': len([x for x in all_adherence_data if x >= 80]),
                'good_60_79': len([x for x in all_adherence_data if 60 <= x < 80]),
                'poor_below_60': len([x for x in all_adherence_data if x < 60])
            }
        }