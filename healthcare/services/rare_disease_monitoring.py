# healthcare/services/rare_disease_monitoring.py
from django.utils import timezone
from django.db.models import Q, Count, Avg
from datetime import timedelta
from typing import Dict, List, Any, Optional
import logging

from ..models import Condition, Symptom, LabResult, RareConditionRegistry
from medication.models import Medication, AdherenceRecord
from wearables.models import WearableMeasurement

logger = logging.getLogger(__name__)

class RareDiseaseMonitoringService:
    """
    Service for monitoring rare disease patients and generating insights.
    Critical for pharmaceutical companies and healthcare providers.
    """
    
    @classmethod
    def monitor_patient_progression(cls, patient_id: str, condition_id: str, days: int = 90) -> Dict[str, Any]:
        """
        Monitor progression of a rare disease patient.
        Tracks symptoms, biomarkers, medication adherence, and quality of life.
        """
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            
            patient = User.objects.get(id=patient_id)
            condition = Condition.objects.get(id=condition_id, is_rare_condition=True)
            
            end_date = timezone.now().date()
            start_date = end_date - timedelta(days=days)
            
            # Get progression metrics
            progression_data = {
                'patient_id': patient_id,
                'condition': {
                    'name': condition.name,
                    'diagnosed_date': condition.diagnosed_date.isoformat() if condition.diagnosed_date else None,
                    'registry_info': cls._get_registry_info(condition.rare_condition) if condition.rare_condition else None
                },
                'symptom_progression': cls._analyze_symptom_progression(condition, start_date, end_date),
                'biomarker_trends': cls._analyze_biomarker_trends(condition, start_date, end_date),
                'medication_response': cls._analyze_medication_response(patient, condition, start_date, end_date),
                'quality_of_life': cls._assess_quality_of_life(patient, start_date, end_date),
                'wearable_insights': cls._get_wearable_insights(patient, start_date, end_date),
                'clinical_alerts': cls._generate_clinical_alerts(patient, condition, start_date, end_date)
            }
            
            return progression_data
            
        except Exception as e:
            logger.error(f"Error monitoring patient progression: {str(e)}")
            return {'error': str(e)}
    
    @classmethod
    def generate_cohort_analysis(cls, rare_condition_id: str, 
                               pharmaceutical_company_id: str = None) -> Dict[str, Any]:
        """
        Generate cohort analysis for patients with specific rare condition.
        Used by pharmaceutical companies for research and drug development.
        """
        try:
            rare_condition = RareConditionRegistry.objects.get(id=rare_condition_id)
            
            # Get patients with this condition
            patients_query = Condition.objects.filter(
                rare_condition=rare_condition,
                is_rare_condition=True,
                status='active'
            ).values_list('medical_record__patient', flat=True)
            
            # Filter by pharmaceutical company access if specified
            if pharmaceutical_company_id:
                patients_query = patients_query.filter(
                    medical_record__patient__patient_profile__protocol_adherence_monitoring=True
                )
            
            patient_ids = list(patients_query)
            
            cohort_data = {
                'condition': {
                    'name': rare_condition.name,
                    'identifier': rare_condition.identifier,
                    'prevalence': rare_condition.prevalence
                },
                'cohort_size': len(patient_ids),
                'demographics': cls._analyze_cohort_demographics(patient_ids),
                'treatment_patterns': cls._analyze_treatment_patterns(patient_ids, rare_condition),
                'outcomes': cls._analyze_cohort_outcomes(patient_ids, rare_condition),
                'biomarker_correlations': cls._analyze_biomarker_correlations(patient_ids, rare_condition),
                'adherence_patterns': cls._analyze_cohort_adherence(patient_ids),
                'safety_profile': cls._analyze_safety_profile(patient_ids, rare_condition)
            }
            
            return cohort_data
            
        except Exception as e:
            logger.error(f"Error generating cohort analysis: {str(e)}")
            return {'error': str(e)}
    
    @classmethod
    def _analyze_symptom_progression(cls, condition: Condition, start_date, end_date) -> Dict[str, Any]:
        """Analyze how symptoms have changed over time."""
        
        symptoms = Symptom.objects.filter(
            condition=condition,
            last_observed__gte=start_date
        ).order_by('last_observed')
        
        # Track severity changes
        severity_trend = []
        for symptom in symptoms:
            severity_trend.append({
                'symptom': symptom.name,
                'severity': symptom.severity,
                'date': symptom.last_observed.isoformat(),
                'frequency': symptom.frequency,
                'impact': symptom.impact_daily_life
            })
        
        # Calculate averages
        avg_severity = symptoms.aggregate(Avg('severity'))['severity__avg'] or 0
        avg_impact = symptoms.aggregate(Avg('impact_daily_life'))['impact_daily_life__avg'] or 0
        
        return {
            'total_symptoms': symptoms.count(),
            'active_symptoms': symptoms.filter(is_active=True).count(),
            'average_severity': round(avg_severity, 1),
            'average_impact': round(avg_impact, 1),
            'severity_trend': severity_trend,
            'most_severe_symptoms': [
                {
                    'name': s.name,
                    'severity': s.severity,
                    'impact': s.impact_daily_life
                }
                for s in symptoms.order_by('-severity')[:5]
            ]
        }
    
    @classmethod
    def _analyze_biomarker_trends(cls, condition: Condition, start_date, end_date) -> Dict[str, Any]:
        """Analyze biomarker trends for rare condition monitoring."""
        
        # Get lab results related to this condition
        lab_results = LabResult.objects.filter(
            lab_test__medical_record=condition.medical_record,
            lab_test__for_rare_condition_monitoring=True,
            lab_test__related_condition=condition,
            result_date__gte=start_date,
            result_date__lte=end_date
        ).order_by('result_date')
        
        # Group by test type
        biomarker_trends = {}
        for result in lab_results:
            test_name = result.test_name
            if test_name not in biomarker_trends:
                biomarker_trends[test_name] = []
            
            biomarker_trends[test_name].append({
                'value': result.value,
                'unit': result.unit,
                'date': result.result_date.isoformat(),
                'is_abnormal': result.is_abnormal,
                'reference_range': result.reference_range,
                'significance': result.biomarker_significance
            })
        
        return {
            'biomarker_count': len(biomarker_trends),
            'total_measurements': lab_results.count(),
            'abnormal_results': lab_results.filter(is_abnormal=True).count(),
            'trends': biomarker_trends,
            'latest_results': cls._get_latest_biomarkers(lab_results)
        }
    
    @classmethod
    def _analyze_medication_response(cls, patient, condition: Condition, start_date, end_date) -> Dict[str, Any]:
        """Analyze medication response for rare condition treatments."""
        
        # Get medications for this condition
        condition_medications = Medication.objects.filter(
            patient=patient,
            for_rare_condition=True,
            active=True
        )
        
        # Get adherence data
        adherence_data = []
        for medication in condition_medications:
            adherence_records = AdherenceRecord.objects.filter(
                medication=medication,
                period_start__gte=start_date,
                period_end__lte=end_date
            )
            
            if adherence_records.exists():
                avg_adherence = adherence_records.aggregate(Avg('adherence_rate'))['adherence_rate__avg']
                adherence_data.append({
                    'medication': medication.name,
                    'dosage': medication.dosage,
                    'adherence_rate': round(avg_adherence, 1),
                    'protocol_number': medication.protocol_number,
                    'orphan_drug': medication.orphan_drug,
                    'requires_monitoring': medication.requires_lab_monitoring
                })
        
        return {
            'total_medications': condition_medications.count(),
            'orphan_drugs': condition_medications.filter(orphan_drug=True).count(),
            'adherence_data': adherence_data,
            'average_adherence': round(
                sum(med['adherence_rate'] for med in adherence_data) / len(adherence_data)
                if adherence_data else 0, 1
            ),
            'monitoring_required': condition_medications.filter(requires_lab_monitoring=True).count()
        }
    
    @classmethod
    def _assess_quality_of_life(cls, patient, start_date, end_date) -> Dict[str, Any]:
        """Assess quality of life based on symptoms and functionality."""
        
        # Get all symptoms for patient
        symptoms = Symptom.objects.filter(
            condition__medical_record__patient=patient,
            last_observed__gte=start_date
        )
        
        if not symptoms.exists():
            return {'score': None, 'message': 'No symptom data available'}
        
        # Calculate quality of life score (0-100, higher is better)
        total_impact = symptoms.aggregate(Avg('impact_daily_life'))['impact_daily_life__avg'] or 0
        total_severity = symptoms.aggregate(Avg('severity'))['severity__avg'] or 0
        
        # Quality of life score (inverted because higher impact/severity = lower QoL)
        qol_score = 100 - ((total_impact + total_severity) / 2 * 10)
        
        return {
            'score': max(0, round(qol_score, 1)),
            'factors': {
                'average_symptom_impact': round(total_impact, 1),
                'average_symptom_severity': round(total_severity, 1),
                'active_symptoms': symptoms.filter(is_active=True).count()
            },
            'interpretation': cls._interpret_qol_score(qol_score)
        }
    
    @classmethod
    def _get_wearable_insights(cls, patient, start_date, end_date) -> Dict[str, Any]:
        """Get insights from wearable device data."""
        
        wearable_data = WearableMeasurement.objects.filter(
            user=patient,
            measured_at__gte=start_date,
            measured_at__lte=end_date
        )
        
        if not wearable_data.exists():
            return {'available': False, 'message': 'No wearable data available'}
        
        # Analyze key metrics
        insights = {
            'available': True,
            'total_measurements': wearable_data.count(),
            'metrics': {},
            'activity_patterns': cls._analyze_activity_patterns(wearable_data),
            'health_correlations': cls._analyze_health_correlations(wearable_data, patient)
        }
        
        # Group by measurement type
        for measurement_type in ['heart_rate', 'steps', 'sleep', 'activity']:
            type_data = wearable_data.filter(measurement_type=measurement_type)
            if type_data.exists():
                insights['metrics'][measurement_type] = {
                    'average': round(type_data.aggregate(Avg('value'))['value__avg'], 1),
                    'count': type_data.count(),
                    'latest': type_data.order_by('-measured_at').first().measured_at.isoformat()
                }
        
        return insights
    
    @classmethod
    def _generate_clinical_alerts(cls, patient, condition: Condition, start_date, end_date) -> List[Dict[str, Any]]:
        """Generate clinical alerts for rare disease monitoring."""
        
        alerts = []
        
        # Check for worsening symptoms
        recent_symptoms = Symptom.objects.filter(
            condition=condition,
            last_observed__gte=timezone.now().date() - timedelta(days=7),
            severity__gte=8
        )
        
        for symptom in recent_symptoms:
            alerts.append({
                'type': 'severe_symptom',
                'priority': 'high',
                'message': f'Severe symptom reported: {symptom.name} (severity: {symptom.severity}/10)',
                'date': symptom.last_observed.isoformat(),
                'action_required': 'Contact patient for clinical assessment'
            })
        
        # Check for abnormal biomarkers
        abnormal_labs = LabResult.objects.filter(
            lab_test__medical_record=condition.medical_record,
            lab_test__related_condition=condition,
            is_abnormal=True,
            result_date__gte=timezone.now().date() - timedelta(days=7)
        )
        
        for lab in abnormal_labs:
            alerts.append({
                'type': 'abnormal_biomarker',
                'priority': 'high',
                'message': f'Abnormal {lab.test_name}: {lab.value} {lab.unit}',
                'date': lab.result_date.isoformat(),
                'action_required': 'Review results and adjust treatment if necessary'
            })
        
        # Check for poor medication adherence
        poor_adherence = AdherenceRecord.objects.filter(
            patient=patient,
            medication__for_rare_condition=True,
            adherence_rate__lt=70,
            period_end__gte=timezone.now().date() - timedelta(days=7)
        )
        
        for adherence in poor_adherence:
            alerts.append({
                'type': 'poor_adherence',
                'priority': 'medium',
                'message': f'Poor adherence to {adherence.medication.name}: {adherence.adherence_rate}%',
                'date': adherence.period_end.isoformat(),
                'action_required': 'Contact patient to discuss adherence barriers'
            })
        
        return sorted(alerts, key=lambda x: x['priority'] == 'high', reverse=True)
    
    @classmethod
    def _interpret_qol_score(cls, score: float) -> str:
        """Interpret quality of life score."""
        if score >= 80:
            return 'Good quality of life'
        elif score >= 60:
            return 'Moderate quality of life'
        elif score >= 40:
            return 'Poor quality of life'
        else:
            return 'Very poor quality of life'