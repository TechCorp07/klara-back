# healthcare/services/dashboard_service.py
from django.utils import timezone
from django.db.models import Count, Avg, F
from datetime import timedelta, date
from typing import Dict, List, Any
import logging

from ..models import MedicalRecord, Condition, VitalSign, LabTest, LabResult, Symptom
from medication.models import Medication, AdherenceRecord
from users.models import User

logger = logging.getLogger(__name__)

class HealthcareDashboardService:
    """
    Service for generating healthcare dashboard data.
    Critical for rare disease patient monitoring and care coordination.
    """
    
    @classmethod
    def get_patient_dashboard_data(cls, patient: User, days: int = 30) -> Dict[str, Any]:
        """
        Generate comprehensive dashboard data for a patient.
        Focused on rare disease monitoring and medication adherence.
        """
        try:
            end_date = timezone.now().date()
            start_date = end_date - timedelta(days=days)
            
            # Get medical record
            medical_record = MedicalRecord.objects.filter(patient=patient).first()
            if not medical_record:
                return {'error': 'No medical record found'}
            
            # Basic patient info
            dashboard_data = {
                'patient_info': {
                    'name': patient.get_full_name(),
                    'email': patient.email,
                    'has_rare_condition': medical_record.has_rare_condition,
                    'rare_conditions': cls._get_rare_conditions_summary(medical_record),
                },
                'summary': cls._get_health_summary(medical_record, start_date, end_date),
                'medications': cls._get_medication_summary(patient, start_date, end_date),
                'vitals': cls._get_vitals_summary(medical_record, start_date, end_date),
                'symptoms': cls._get_symptoms_summary(medical_record, start_date, end_date),
                'lab_results': cls._get_lab_results_summary(medical_record, start_date, end_date),
                'wearable_data': cls._get_wearable_data_summary(patient, start_date, end_date),
                'care_team': cls._get_care_team_info(medical_record),
                'upcoming_appointments': cls._get_upcoming_appointments(patient),
                'alerts': cls._get_health_alerts(patient, medical_record)
            }
            
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Error generating patient dashboard: {str(e)}")
            return {'error': str(e)}
    
    @classmethod
    def get_provider_dashboard_data(cls, provider: User, days: int = 30) -> Dict[str, Any]:
        """
        Generate dashboard data for healthcare providers.
        Focused on rare disease patient management and care coordination.
        """
        try:
            end_date = timezone.now().date()
            start_date = end_date - timedelta(days=days)
            
            # Get provider's patients
            patients = cls._get_provider_patients(provider)
            
            dashboard_data = {
                'provider_info': {
                    'name': provider.get_full_name(),
                    'specialty': getattr(provider.provider_profile, 'specialty', 'General') if hasattr(provider, 'provider_profile') else 'General',
                    'total_patients': patients.count(),
                    'rare_disease_patients': patients.filter(medical_records__has_rare_condition=True).count()
                },
                'patient_summary': cls._get_provider_patient_summary(patients, start_date, end_date),
                'medication_adherence': cls._get_provider_adherence_summary(patients, start_date, end_date),
                'critical_alerts': cls._get_provider_critical_alerts(patients),
                'recent_lab_results': cls._get_provider_lab_results(patients, start_date, end_date),
                'upcoming_appointments': cls._get_provider_upcoming_appointments(provider),
                'symptom_trends': cls._get_provider_symptom_trends(patients, start_date, end_date)
            }
            
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Error generating provider dashboard: {str(e)}")
            return {'error': str(e)}
    
    @classmethod
    def get_pharmco_dashboard_data(cls, pharmco_user: User, days: int = 30) -> Dict[str, Any]:
        """
        Generate dashboard data for pharmaceutical companies.
        Focused on drug protocol monitoring and research data.
        """
        try:
            end_date = timezone.now().date()
            start_date = end_date - timedelta(days=days)
            
            # Get patients with protocol adherence monitoring consent
            consented_patients = User.objects.filter(
                role='patient',
                patient_profile__protocol_adherence_monitoring=True,
                patient_profile__custom_drug_protocols__isnull=False
            )
            
            dashboard_data = {
                'company_info': {
                    'name': getattr(pharmco_user.pharmco_profile, 'company_name', 'Unknown') if hasattr(pharmco_user, 'pharmco_profile') else 'Unknown',
                    'total_patients': consented_patients.count(),
                    'active_protocols': cls._get_active_protocols_count(consented_patients)
                },
                'adherence_metrics': cls._get_pharmco_adherence_metrics(consented_patients, start_date, end_date),
                'safety_signals': cls._get_safety_signals(consented_patients, start_date, end_date),
                'efficacy_data': cls._get_efficacy_data(consented_patients, start_date, end_date),
                'patient_reported_outcomes': cls._get_patient_reported_outcomes(consented_patients, start_date, end_date),
                'biomarker_trends': cls._get_biomarker_trends(consented_patients, start_date, end_date),
                'adverse_events': cls._get_adverse_events_summary(consented_patients, start_date, end_date)
            }
            
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Error generating pharmaceutical dashboard: {str(e)}")
            return {'error': str(e)}
    
    @classmethod
    def _get_rare_conditions_summary(cls, medical_record: MedicalRecord) -> List[Dict[str, Any]]:
        """Get summary of rare conditions for patient."""
        conditions = Condition.objects.filter(
            medical_record=medical_record,
            is_rare_condition=True,
            status='active'
        ).select_related('rare_condition')
        
        return [
            {
                'name': condition.name,
                'diagnosed_date': condition.diagnosed_date.isoformat() if condition.diagnosed_date else None,
                'registry_info': {
                    'identifier': condition.rare_condition.identifier if condition.rare_condition else None,
                    'prevalence': condition.rare_condition.prevalence if condition.rare_condition else None,
                    'specialty': condition.rare_condition.specialty_category if condition.rare_condition else None
                } if condition.rare_condition else None,
                'biomarker_status': condition.biomarker_status,
                'last_assessment': condition.last_assessment_date.isoformat() if condition.last_assessment_date else None
            }
            for condition in conditions
        ]
    
    @classmethod
    def _get_health_summary(cls, medical_record: MedicalRecord, start_date: date, end_date: date) -> Dict[str, Any]:
        """Get overall health summary for patient."""
        
        # Get condition counts
        active_conditions = Condition.objects.filter(
            medical_record=medical_record,
            status='active'
        ).count()
        
        rare_conditions = Condition.objects.filter(
            medical_record=medical_record,
            is_rare_condition=True,
            status='active'
        ).count()
        
        # Get recent vitals
        recent_vitals = VitalSign.objects.filter(
            medical_record=medical_record,
            measured_at__gte=start_date,
            measured_at__lte=end_date
        ).count()
        
        # Get lab tests
        recent_labs = LabTest.objects.filter(
            medical_record=medical_record,
            ordered_date__gte=start_date,
            ordered_date__lte=end_date
        ).count()
        
        # Get symptoms
        active_symptoms = Symptom.objects.filter(
            condition__medical_record=medical_record,
            is_active=True,
            last_observed__gte=start_date
        ).count()
        
        return {
            'active_conditions': active_conditions,
            'rare_conditions': rare_conditions,
            'recent_vitals': recent_vitals,
            'recent_labs': recent_labs,
            'active_symptoms': active_symptoms,
            'health_score': cls._calculate_health_score(medical_record, start_date, end_date)
        }
    
    @classmethod
    def _get_medication_summary(cls, patient: User, start_date: date, end_date: date) -> Dict[str, Any]:
        """Get medication summary with adherence data."""
        
        # Get active medications
        active_medications = Medication.objects.filter(
            patient=patient,
            active=True
        )
        
        # Get adherence records
        adherence_records = AdherenceRecord.objects.filter(
            patient=patient,
            period_start__gte=start_date,
            period_end__lte=end_date
        )
        
        # Calculate averages
        avg_adherence = adherence_records.aggregate(
            avg_rate=Avg('adherence_rate')
        )['avg_rate'] or 0
        
        # Get rare disease medications
        rare_disease_meds = active_medications.filter(for_rare_condition=True)
        
        return {
            'total_medications': active_medications.count(),
            'rare_disease_medications': rare_disease_meds.count(),
            'average_adherence': round(avg_adherence, 1),
            'adherence_trend': cls._get_adherence_trend(adherence_records),
            'critical_medications': cls._get_critical_medications(rare_disease_meds)
        }
    
    @classmethod
    def _get_vitals_summary(cls, medical_record: MedicalRecord, start_date: date, end_date: date) -> Dict[str, Any]:
        """Get vitals summary with trends."""
        
        vitals = VitalSign.objects.filter(
            medical_record=medical_record,
            measured_at__gte=start_date,
            measured_at__lte=end_date
        ).order_by('-measured_at')
        
        # Group by measurement type
        vitals_by_type = {}
        for vital in vitals:
            if vital.measurement_type not in vitals_by_type:
                vitals_by_type[vital.measurement_type] = []
            vitals_by_type[vital.measurement_type].append({
                'value': vital.value,
                'unit': vital.unit,
                'measured_at': vital.measured_at.isoformat(),
                'is_abnormal': vital.is_abnormal,
                'source': vital.source
            })
        
        # Get latest values
        latest_vitals = {}
        for measurement_type in vitals_by_type:
            if vitals_by_type[measurement_type]:
                latest_vitals[measurement_type] = vitals_by_type[measurement_type][0]
        
        return {
            'total_measurements': vitals.count(),
            'abnormal_readings': vitals.filter(is_abnormal=True).count(),
            'latest_vitals': latest_vitals,
            'trends': vitals_by_type,
            'wearable_integration': cls._check_wearable_integration(medical_record.patient)
        }
    
    @classmethod
    def _get_health_alerts(cls, patient: User, medical_record: MedicalRecord) -> List[Dict[str, Any]]:
        """Get critical health alerts for patient."""
        alerts = []
        
        # Check for overdue lab results
        overdue_labs = LabTest.objects.filter(
            medical_record=medical_record,
            status='pending',
            ordered_date__lt=timezone.now() - timedelta(days=7)
        )
        
        for lab in overdue_labs:
            alerts.append({
                'type': 'overdue_lab',
                'priority': 'high',
                'message': f'Lab test "{lab.name}" is overdue',
                'created_at': lab.ordered_date.isoformat()
            })
        
        # Check for medication adherence issues
        from medication.models import AdherenceRecord
        
        poor_adherence = AdherenceRecord.objects.filter(
            patient=patient,
            medication__for_rare_condition=True,
            adherence_rate__lt=80,
            period_end__gte=timezone.now().date() - timedelta(days=7)
        )
        
        for adherence in poor_adherence:
            alerts.append({
                'type': 'poor_adherence',
                'priority': 'high',
                'message': f'Low adherence for {adherence.medication.name}: {adherence.adherence_rate}%',
                'created_at': adherence.period_end.isoformat()
            })
        
        # Check for abnormal vitals
        abnormal_vitals = VitalSign.objects.filter(
            medical_record=medical_record,
            is_abnormal=True,
            measured_at__gte=timezone.now() - timedelta(days=3)
        )
        
        for vital in abnormal_vitals:
            alerts.append({
                'type': 'abnormal_vital',
                'priority': 'medium',
                'message': f'Abnormal {vital.measurement_type}: {vital.value} {vital.unit}',
                'created_at': vital.measured_at.isoformat()
            })
        
        return sorted(alerts, key=lambda x: x['created_at'], reverse=True)
    
    @classmethod
    def _calculate_health_score(cls, medical_record: MedicalRecord, start_date: date, end_date: date) -> float:
        """Calculate overall health score based on multiple factors."""
        
        score = 100.0  # Start with perfect score
        
        # Deduct for active conditions
        active_conditions = Condition.objects.filter(
            medical_record=medical_record,
            status='active'
        ).count()
        score -= (active_conditions * 5)  # 5 points per active condition
        
        # Deduct more for rare conditions
        rare_conditions = Condition.objects.filter(
            medical_record=medical_record,
            is_rare_condition=True,
            status='active'
        ).count()
        score -= (rare_conditions * 10)  # Additional 10 points per rare condition
        
        # Deduct for abnormal vitals
        abnormal_vitals = VitalSign.objects.filter(
            medical_record=medical_record,
            is_abnormal=True,
            measured_at__gte=start_date
        ).count()
        score -= (abnormal_vitals * 2)  # 2 points per abnormal vital
        
        # Deduct for poor medication adherence
        from medication.models import AdherenceRecord
        poor_adherence = AdherenceRecord.objects.filter(
            patient=medical_record.patient,
            adherence_rate__lt=80,
            period_end__gte=start_date
        ).count()
        score -= (poor_adherence * 15)  # 15 points per poor adherence period
        
        # Ensure score doesn't go below 0
        return max(0, score)
    
    @classmethod
    def _get_adherence_trend(cls, adherence_records) -> List[Dict[str, Any]]:
        """Get adherence trend data for charting."""
        return [
            {
                'date': record.period_end.isoformat(),
                'rate': record.adherence_rate,
                'medication': record.medication.name
            }
            for record in adherence_records.order_by('period_end')
        ]
    
    @classmethod
    def _get_critical_medications(cls, rare_disease_meds) -> List[Dict[str, Any]]:
        """Get critical medications that need special attention."""
        return [
            {
                'name': med.name,
                'dosage': med.dosage,
                'orphan_drug': med.orphan_drug,
                'requires_monitoring': med.requires_lab_monitoring,
                'protocol_number': med.protocol_number
            }
            for med in rare_disease_meds
            if med.orphan_drug or med.requires_lab_monitoring
        ]
    
    @classmethod
    def _check_wearable_integration(cls, patient: User) -> Dict[str, Any]:
        """Check wearable device integration status."""
        from wearables.models import WearableIntegration
        
        active_integrations = WearableIntegration.objects.filter(
            user=patient,
            status='connected'
        )
        
        return {
            'has_wearable': active_integrations.exists(),
            'device_count': active_integrations.count(),
            'last_sync': active_integrations.order_by('-last_sync').first().last_sync.isoformat() if active_integrations.exists() else None
        }