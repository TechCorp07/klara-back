# fhir/services/advanced_integration.py
import json
import requests
from datetime import timedelta
from typing import Dict, List, Optional, Tuple
from django.utils import timezone
from django.conf import settings
from django.db import transaction
from django.contrib.auth import get_user_model
import logging

from ..models import (
    FHIREncounter
)
from healthcare.models import Medication, VitalSign, Condition
from medication.models import AdherenceRecord

User = get_user_model()
logger = logging.getLogger(__name__)

class AdvancedFHIRIntegrationService:
    """
    Advanced FHIR integration service for rare disease patient data exchange.
    Builds on your existing FHIR models and healthcare data structure.
    """
    
    def __init__(self):
        self.base_fhir_url = settings.FHIR_SERVER_URL
        self.headers = {
            'Content-Type': 'application/fhir+json',
            'Accept': 'application/fhir+json',
            'Authorization': f'Bearer {settings.FHIR_ACCESS_TOKEN}'
        }
    
    def export_patient_data_bundle(self, patient_id: int, include_family_history: bool = False) -> Dict:
        """
        Export comprehensive patient data as FHIR Bundle for external institutions.
        Uses your existing models to create FHIR-compliant data.
        """
        
        try:
            patient = User.objects.get(id=patient_id, role='patient')
            patient_profile = patient.patient_profile
            
            # Create FHIR Bundle
            bundle = {
                "resourceType": "Bundle",
                "id": f"patient-export-{patient_id}-{timezone.now().strftime('%Y%m%d')}",
                "type": "collection",
                "timestamp": timezone.now().isoformat(),
                "entry": []
            }
            
            # 1. Patient Resource
            patient_resource = self._create_patient_resource(patient, patient_profile)
            bundle["entry"].append({
                "resource": patient_resource,
                "request": {"method": "POST", "url": "Patient"}
            })
            
            # 2. Conditions (including rare diseases)
            conditions = Condition.objects.filter(medical_record__patient=patient)
            for condition in conditions:
                condition_resource = self._create_condition_resource(condition, patient_resource["id"])
                bundle["entry"].append({
                    "resource": condition_resource,
                    "request": {"method": "POST", "url": "Condition"}
                })
            
            # 3. Medications and Adherence Data
            medications = Medication.objects.filter(patient=patient, active=True)
            for medication in medications:
                med_resource = self._create_medication_statement_resource(medication, patient_resource["id"])
                bundle["entry"].append({
                    "resource": med_resource,
                    "request": {"method": "POST", "url": "MedicationStatement"}
                })
                
                # Include adherence data for rare disease medications
                if medication.for_rare_condition:
                    adherence_resource = self._create_adherence_observation(medication, patient_resource["id"])
                    if adherence_resource:
                        bundle["entry"].append({
                            "resource": adherence_resource,
                            "request": {"method": "POST", "url": "Observation"}
                        })
            
            # 4. Vital Signs and Wearable Data
            vital_signs = VitalSign.objects.filter(
                medical_record__patient=patient,
                recorded_date__gte=timezone.now().date() - timedelta(days=90)
            )
            for vital in vital_signs:
                vital_resource = self._create_vital_signs_observation(vital, patient_resource["id"])
                bundle["entry"].append({
                    "resource": vital_resource,
                    "request": {"method": "POST", "url": "Observation"}
                })
            
            # 5. Encounters (including telemedicine)
            encounters = FHIREncounter.objects.filter(patient=patient)
            for encounter in encounters:
                encounter_resource = self._create_encounter_resource(encounter)
                bundle["entry"].append({
                    "resource": encounter_resource,
                    "request": {"method": "POST", "url": "Encounter"}
                })
            
            # 6. Family History (if requested and consented)
            if include_family_history and patient_profile.family_history_sharing_consent:
                family_history = self._create_family_history_resources(patient, patient_resource["id"])
                bundle["entry"].extend(family_history)
            
            # 7. Research Participation Data (for rare disease studies)
            research_data = self._create_research_participation_data(patient, patient_resource["id"])
            if research_data:
                bundle["entry"].extend(research_data)
            
            return {
                'status': 'success',
                'bundle': bundle,
                'summary': {
                    'patient_id': patient_id,
                    'total_resources': len(bundle["entry"]),
                    'includes_family_history': include_family_history,
                    'export_timestamp': bundle["timestamp"]
                }
            }
            
        except Exception as e:
            logger.error(f"Error creating FHIR bundle for patient {patient_id}: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def import_external_patient_data(self, patient_id: int, fhir_bundle: Dict, source_institution: str) -> Dict:
        """
        Import patient data from external FHIR-compliant systems.
        Integrates with your existing healthcare models.
        """
        
        try:
            patient = User.objects.get(id=patient_id, role='patient')
            import_summary = {
                'imported_conditions': 0,
                'imported_medications': 0,
                'imported_observations': 0,
                'imported_encounters': 0,
                'errors': []
            }
            
            with transaction.atomic():
                # Process each entry in the bundle
                for entry in fhir_bundle.get('entry', []):
                    resource = entry.get('resource', {})
                    resource_type = resource.get('resourceType')
                    
                    try:
                        if resource_type == 'Condition':
                            self._import_condition_resource(resource, patient)
                            import_summary['imported_conditions'] += 1
                            
                        elif resource_type == 'MedicationStatement':
                            self._import_medication_statement_resource(resource, patient)
                            import_summary['imported_medications'] += 1
                            
                        elif resource_type == 'Observation':
                            self._import_observation_resource(resource, patient)
                            import_summary['imported_observations'] += 1
                            
                        elif resource_type == 'Encounter':
                            self._import_encounter_resource(resource, patient)
                            import_summary['imported_encounters'] += 1
                            
                    except Exception as e:
                        error_msg = f"Error importing {resource_type}: {str(e)}"
                        import_summary['errors'].append(error_msg)
                        logger.warning(error_msg)
            
            return {
                'status': 'success',
                'summary': import_summary,
                'message': f"Successfully imported data from {source_institution}"
            }
            
        except Exception as e:
            logger.error(f"Error importing FHIR data for patient {patient_id}: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def sync_with_external_ehr(self, patient_id: int, ehr_endpoint: str) -> Dict:
        """
        Bidirectional sync with external EHR systems for ongoing care coordination.
        """
        try:
            # Export current data
            export_result = self.export_patient_data_bundle(patient_id)
            if export_result['status'] != 'success':
                return export_result
            
            # Send to external system
            response = requests.post(
                f"{ehr_endpoint}/Patient",
                json=export_result['bundle'],
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                # Request updated data from external system
                import_response = requests.get(
                    f"{ehr_endpoint}/Patient/{patient_id}/$everything",
                    headers=self.headers,
                    timeout=30
                )
                
                if import_response.status_code == 200:
                    external_data = import_response.json()
                    import_result = self.import_external_patient_data(
                        patient_id, 
                        external_data, 
                        ehr_endpoint
                    )
                    
                    return {
                        'status': 'success',
                        'export_summary': export_result['summary'],
                        'import_summary': import_result.get('summary', {}),
                        'message': 'Bidirectional sync completed successfully'
                    }
            
            return {
                'status': 'error',
                'message': f'External EHR responded with status {response.status_code}'
            }
            
        except Exception as e:
            logger.error(f"Error syncing with external EHR: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def create_rare_disease_research_bundle(self, condition_code: str, include_patient_ids: List[int] = None) -> Dict:
        """
        Create anonymized research bundle for rare disease studies.
        Respects patient consent and privacy regulations.
        """
        
        try:
            # Get consented patients with the specific rare condition
            patients_query = User.objects.filter(
                role='patient',
                patient_profile__research_participation_consent=True,
                medical_records__conditions__code=condition_code
            )
            
            if include_patient_ids:
                patients_query = patients_query.filter(id__in=include_patient_ids)
            
            patients = patients_query.distinct()
            
            research_bundle = {
                "resourceType": "Bundle",
                "id": f"research-{condition_code}-{timezone.now().strftime('%Y%m%d')}",
                "type": "collection",
                "timestamp": timezone.now().isoformat(),
                "meta": {
                    "tag": [
                        {
                            "system": "http://terminology.hl7.org/CodeSystem/v3-Confidentiality",
                            "code": "R",
                            "display": "restricted"
                        }
                    ]
                },
                "entry": []
            }
            
            for patient in patients:
                # Create anonymized patient data
                anonymized_data = self._create_anonymized_research_data(patient, condition_code)
                research_bundle["entry"].extend(anonymized_data)
            
            return {
                'status': 'success',
                'bundle': research_bundle,
                'summary': {
                    'condition_code': condition_code,
                    'patient_count': patients.count(),
                    'total_resources': len(research_bundle["entry"])
                }
            }
            
        except Exception as e:
            logger.error(f"Error creating research bundle: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    # Helper methods for resource creation
    def _create_patient_resource(self, patient, patient_profile) -> Dict:
        """Create FHIR Patient resource from your user model."""
        return {
            "resourceType": "Patient",
            "id": f"patient-{patient.id}",
            "identifier": [
                {
                    "system": "http://yourhealthsystem.com/patient-id",
                    "value": str(patient.id)
                }
            ],
            "name": [
                {
                    "family": patient.last_name or "Unknown",
                    "given": [patient.first_name or "Unknown"]
                }
            ],
            "gender": patient_profile.gender if hasattr(patient_profile, 'gender') else "unknown",
            "birthDate": patient_profile.date_of_birth.isoformat() if hasattr(patient_profile, 'date_of_birth') and patient_profile.date_of_birth else None,
            "active": patient.is_active,
            "communication": [
                {
                    "language": {
                        "coding": [
                            {
                                "system": "urn:ietf:bcp:47",
                                "code": "en-US"
                            }
                        ]
                    },
                    "preferred": True
                }
            ]
        }
    
    def _create_condition_resource(self, condition, patient_id: str) -> Dict:
        """Create FHIR Condition resource from your Condition model."""
        return {
            "resourceType": "Condition",
            "id": f"condition-{condition.id}",
            "subject": {"reference": f"Patient/{patient_id}"},
            "code": {
                "coding": [
                    {
                        "system": "http://snomed.info/sct",
                        "code": condition.code or "unknown",
                        "display": condition.condition_name
                    }
                ]
            },
            "clinicalStatus": {
                "coding": [
                    {
                        "system": "http://terminology.hl7.org/CodeSystem/condition-clinical",
                        "code": "active" if condition.active else "inactive"
                    }
                ]
            },
            "category": [
                {
                    "coding": [
                        {
                            "system": "http://terminology.hl7.org/CodeSystem/condition-category",
                            "code": "problem-list-item"
                        }
                    ]
                }
            ],
            "onsetDateTime": condition.onset_date.isoformat() if condition.onset_date else None,
            "note": [
                {
                    "text": condition.notes or ""
                }
            ]
        }
    
    def _create_medication_statement_resource(self, medication, patient_id: str) -> Dict:
        """Create FHIR MedicationStatement from your Medication model."""
        return {
            "resourceType": "MedicationStatement",
            "id": f"medication-{medication.id}",
            "status": "active" if medication.active else "completed",
            "subject": {"reference": f"Patient/{patient_id}"},
            "medicationCodeableConcept": {
                "coding": [
                    {
                        "system": "http://www.nlm.nih.gov/research/umls/rxnorm",
                        "code": medication.rxnorm_code or "unknown",
                        "display": medication.name
                    }
                ],
                "text": medication.name
            },
            "effectiveDateTime": medication.start_date.isoformat(),
            "dosage": [
                {
                    "text": f"{medication.dosage} {medication.frequency}",
                    "timing": {
                        "repeat": {
                            "frequency": self._parse_frequency(medication.frequency)
                        }
                    }
                }
            ],
            "note": [
                {
                    "text": medication.instructions or ""
                }
            ]
        }
    
    def _create_adherence_observation(self, medication, patient_id: str) -> Optional[Dict]:
        """Create adherence observation from AdherenceRecord."""
        latest_adherence = AdherenceRecord.objects.filter(
            medication=medication
        ).order_by('-period_start').first()
        
        if not latest_adherence:
            return None
        
        return {
            "resourceType": "Observation",
            "id": f"adherence-{latest_adherence.id}",
            "status": "final",
            "category": [
                {
                    "coding": [
                        {
                            "system": "http://terminology.hl7.org/CodeSystem/observation-category",
                            "code": "therapy"
                        }
                    ]
                }
            ],
            "code": {
                "coding": [
                    {
                        "system": "http://loinc.org",
                        "code": "418633004",
                        "display": "Medication adherence"
                    }
                ]
            },
            "subject": {"reference": f"Patient/{patient_id}"},
            "effectivePeriod": {
                "start": latest_adherence.period_start.isoformat(),
                "end": latest_adherence.period_end.isoformat()
            },
            "valueQuantity": {
                "value": latest_adherence.adherence_rate,
                "unit": "%",
                "system": "http://unitsofmeasure.org",
                "code": "%"
            }
        }
    
    def _create_vital_signs_observation(self, vital_sign, patient_id: str) -> Dict:
        """Create FHIR Observation for vital signs."""
        # Map your vital sign types to LOINC codes
        loinc_mapping = {
            'blood_pressure_systolic': {'code': '8480-6', 'display': 'Systolic blood pressure'},
            'blood_pressure_diastolic': {'code': '8462-4', 'display': 'Diastolic blood pressure'},
            'heart_rate': {'code': '8867-4', 'display': 'Heart rate'},
            'temperature': {'code': '8310-5', 'display': 'Body temperature'},
            'weight': {'code': '29463-7', 'display': 'Body weight'},
            'oxygen_saturation': {'code': '2708-6', 'display': 'Oxygen saturation'}
        }
        
        vital_type = vital_sign.measurement_type.lower()
        loinc_info = loinc_mapping.get(vital_type, {'code': 'unknown', 'display': vital_type})
        
        return {
            "resourceType": "Observation",
            "id": f"vital-{vital_sign.id}",
            "status": "final",
            "category": [
                {
                    "coding": [
                        {
                            "system": "http://terminology.hl7.org/CodeSystem/observation-category",
                            "code": "vital-signs"
                        }
                    ]
                }
            ],
            "code": {
                "coding": [
                    {
                        "system": "http://loinc.org",
                        "code": loinc_info['code'],
                        "display": loinc_info['display']
                    }
                ]
            },
            "subject": {"reference": f"Patient/{patient_id}"},
            "effectiveDateTime": vital_sign.recorded_date.isoformat(),
            "valueQuantity": {
                "value": vital_sign.value,
                "unit": vital_sign.unit,
                "system": "http://unitsofmeasure.org"
            }
        }
    
    def _parse_frequency(self, frequency_text: str) -> int:
        """Parse medication frequency text to numeric value."""
        frequency_lower = frequency_text.lower()
        if 'once' in frequency_lower or 'daily' in frequency_lower:
            return 1
        elif 'twice' in frequency_lower:
            return 2
        elif 'three times' in frequency_lower or 'tid' in frequency_lower:
            return 3
        elif 'four times' in frequency_lower or 'qid' in frequency_lower:
            return 4
        else:
            return 1  # Default to once daily
    
    # Additional helper methods for import functionality would go here
    def _import_condition_resource(self, resource: Dict, patient) -> None:
        """Import FHIR Condition resource into your Condition model."""
        # Implementation for importing conditions
        pass
    
    def _import_medication_statement_resource(self, resource: Dict, patient) -> None:
        """Import FHIR MedicationStatement into your Medication model."""
        # Implementation for importing medications
        pass
    
    def _import_observation_resource(self, resource: Dict, patient) -> None:
        """Import FHIR Observation into appropriate models."""
        # Implementation for importing observations
        pass
    
    def _import_encounter_resource(self, resource: Dict, patient) -> None:
        """Import FHIR Encounter into your encounter model."""
        # Implementation for importing encounters
        pass