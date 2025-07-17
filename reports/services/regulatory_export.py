import io
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from django.utils import timezone
from django.conf import settings
import logging

logger = logging.getLogger('hipaa_audit')

class RegulatoryExportService:
    """Export data for regulatory agencies (FDA, EMA, etc.)."""
    
    @staticmethod
    def export_adverse_events_fda(start_date, end_date, medication_ids=None):
        """Export adverse events in FDA-compliant format."""
        from medication.models import SideEffect, Medication
        from healthcare.models import MedicalRecord
        
        # Get side effects for the period
        side_effects = SideEffect.objects.filter(
            reported_date__range=[start_date, end_date],
            medication__for_rare_condition=True
        )
        
        if medication_ids:
            side_effects = side_effects.filter(medication_id__in=medication_ids)
        
        # Create FDA FAERS-compatible XML
        root = ET.Element("AdverseEventReport")
        root.set("version", "1.0")
        root.set("generated", timezone.now().isoformat())
        
        for side_effect in side_effects:
            event = ET.SubElement(root, "AdverseEvent")
            
            # Patient information (anonymized)
            patient_elem = ET.SubElement(event, "Patient")
            ET.SubElement(patient_elem, "PatientID").text = f"ANON_{side_effect.patient.id}"
            ET.SubElement(patient_elem, "Age").text = str(side_effect.patient.age) if hasattr(side_effect.patient, 'age') else "Unknown"
            ET.SubElement(patient_elem, "Gender").text = getattr(side_effect.patient, 'gender', 'Unknown')
            
            # Medication information
            med_elem = ET.SubElement(event, "SuspectMedication")
            ET.SubElement(med_elem, "ProductName").text = side_effect.medication.name
            ET.SubElement(med_elem, "ActiveIngredient").text = side_effect.medication.active_ingredient
            ET.SubElement(med_elem, "Dosage").text = side_effect.medication.dosage
            
            # Event details
            event_elem = ET.SubElement(event, "EventDetails")
            ET.SubElement(event_elem, "Description").text = side_effect.description
            ET.SubElement(event_elem, "Severity").text = side_effect.severity
            ET.SubElement(event_elem, "Outcome").text = side_effect.outcome
            ET.SubElement(event_elem, "ReportDate").text = side_effect.reported_date.isoformat()
            
            # Rare disease indication
            indication_elem = ET.SubElement(event, "Indication")
            ET.SubElement(indication_elem, "RareDisease").text = "True"
            ET.SubElement(indication_elem, "ConditionName").text = side_effect.medication.condition
        
        # Convert to string
        tree = ET.ElementTree(root)
        output = io.StringIO()
        tree.write(output, encoding='unicode', xml_declaration=True)
        
        return output.getvalue()
    
    @staticmethod
    def export_clinical_outcomes_ema(start_date, end_date):
        """Export clinical outcomes in EMA-compatible format."""
        from healthcare.models import MedicalRecord, Treatment
        from medication.models import Medication
        
        # Get treatments for rare diseases
        treatments = Treatment.objects.filter(
            start_date__range=[start_date, end_date],
            medical_record__has_rare_condition=True
        )
        
        # Create CSV for EMA submission
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Headers as per EMA guidelines
        writer.writerow([
            'Patient_ID', 'Age', 'Gender', 'Rare_Disease', 'Treatment_Name',
            'Start_Date', 'End_Date', 'Outcome', 'Efficacy_Score',
            'Quality_of_Life_Score', 'Adverse_Events', 'Discontinued',
            'Reason_Discontinued'
        ])
        
        for treatment in treatments:
            patient = treatment.medical_record.patient
            
            writer.writerow([
                f"ANON_{patient.id}",
                getattr(patient, 'age', 'Unknown'),
                getattr(patient, 'gender', 'Unknown'),
                treatment.medical_record.primary_condition,
                treatment.name,
                treatment.start_date.isoformat(),
                treatment.end_date.isoformat() if treatment.end_date else '',
                treatment.outcome,
                treatment.efficacy_score if hasattr(treatment, 'efficacy_score') else '',
                treatment.qol_score if hasattr(treatment, 'qol_score') else '',
                treatment.adverse_events_count if hasattr(treatment, 'adverse_events_count') else 0,
                'Yes' if treatment.end_date else 'No',
                treatment.discontinuation_reason if hasattr(treatment, 'discontinuation_reason') else ''
            ])
        
        return output.getvalue()
    
    @staticmethod
    def generate_periodic_safety_update(medication_id, period_start, period_end):
        """Generate Periodic Safety Update Report (PSUR) for a medication."""
        from medication.models import Medication, SideEffect, AdherenceRecord
        
        medication = Medication.objects.get(id=medication_id)
        
        # Safety data
        side_effects = SideEffect.objects.filter(
            medication=medication,
            reported_date__range=[period_start, period_end]
        )
        
        # Exposure data
        adherence_records = AdherenceRecord.objects.filter(
            medication=medication,
            taken_at__range=[period_start, period_end]
        )
        
        total_exposure_days = adherence_records.count()
        unique_patients = adherence_records.values('patient').distinct().count()
        
        # Calculate incidence rates
        serious_ae_count = side_effects.filter(severity__in=['severe', 'life_threatening']).count()
        total_ae_count = side_effects.count()
        
        psur_data = {
            'medication_name': medication.name,
            'period_start': period_start.isoformat(),
            'period_end': period_end.isoformat(),
            'total_exposure_days': total_exposure_days,
            'unique_patients_exposed': unique_patients,
            'total_adverse_events': total_ae_count,
            'serious_adverse_events': serious_ae_count,
            'incidence_rate_per_1000_days': (total_ae_count / total_exposure_days * 1000) if total_exposure_days > 0 else 0,
            'serious_ae_rate_per_1000_days': (serious_ae_count / total_exposure_days * 1000) if total_exposure_days > 0 else 0,
            'safety_profile_changes': RegulatoryExportService._assess_safety_changes(medication, period_start, period_end),
            'regulatory_actions_required': RegulatoryExportService._assess_regulatory_actions(medication, side_effects)
        }
        
        return psur_data
    
    @staticmethod
    def _assess_safety_changes(medication, start_date, end_date):
        """Assess if there are significant safety profile changes."""
        # This would implement statistical analysis of safety trends
        # For now, return placeholder analysis
        return {
            'new_safety_signals': False,
            'increased_severity_trend': False,
            'new_adverse_event_types': [],
            'recommendation': 'Continue monitoring'
        }
    
    @staticmethod
    def _assess_regulatory_actions(medication, side_effects):
        """Determine if regulatory actions are needed based on safety data."""
        serious_count = side_effects.filter(severity__in=['severe', 'life_threatening']).count()
        
        if serious_count >= 5:  # Threshold for regulatory attention
            return {
                'action_required': True,
                'urgency': 'High' if serious_count >= 10 else 'Medium',
                'recommended_actions': [
                    'Submit expedited safety report',
                    'Consider risk mitigation measures',
                    'Update prescribing information'
                ]
            }
        
        return {
            'action_required': False,
            'urgency': 'Low',
            'recommended_actions': ['Continue routine monitoring']
        }
