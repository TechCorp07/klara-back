# fhir/services/data_transformation.py
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from django.utils import timezone

from ..models import FHIRPatient, FHIRObservation, FHIRCondition, FHIRMedicationStatement
from healthcare.models import MedicalRecord, VitalSign
from medication.models import Medication

logger = logging.getLogger(__name__)

class DataTransformationService:
    """
    Service for transforming data between internal models and FHIR resources.
    Critical for rare disease data exchange with external systems.
    """
    
    @classmethod
    def transform_external_to_fhir(cls, external_data: Dict[str, Any], 
                                 system_name: str, patient_id: str) -> Dict[str, Any]:
        """
        Transform external EHR data to FHIR format.
        Handles different external system formats.
        """
        try:
            transformed_resources = []
            
            if system_name.lower() == 'epic':
                transformed_resources = cls._transform_epic_data(external_data, patient_id)
            elif system_name.lower() == 'cerner':
                transformed_resources = cls._transform_cerner_data(external_data, patient_id)
            elif system_name.lower() == 'allscripts':
                transformed_resources = cls._transform_allscripts_data(external_data, patient_id)
            else:
                # Generic transformation for unknown systems
                transformed_resources = cls._transform_generic_data(external_data, patient_id)
            
            return {
                'success': True,
                'resources': transformed_resources,
                'count': len(transformed_resources)
            }
            
        except Exception as e:
            logger.error(f"Error transforming external data from {system_name}: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'resources': []
            }
    
    @classmethod
    def _transform_epic_data(cls, epic_data: Dict[str, Any], patient_id: str) -> List[Dict[str, Any]]:
        """Transform Epic EHR data to FHIR format."""
        resources = []
        
        # Transform Epic Patient data
        if 'Patient' in epic_data:
            patient_data = epic_data['Patient']
            fhir_patient = {
                'resourceType': 'Patient',
                'id': patient_id,
                'identifier': [
                    {
                        'system': 'http://epic.com/patient-id',
                        'value': patient_data.get('PatientID', '')
                    }
                ],
                'name': [
                    {
                        'family': patient_data.get('LastName', ''),
                        'given': [patient_data.get('FirstName', '')]
                    }
                ],
                'gender': cls._map_gender(patient_data.get('Gender', '')),
                'birthDate': cls._parse_date(patient_data.get('DateOfBirth', '')),
                'address': cls._transform_epic_address(patient_data.get('Address', {}))
            }
            resources.append(fhir_patient)
        
        # Transform Epic Observations (lab results, vitals)
        if 'Observations' in epic_data:
            for obs_data in epic_data['Observations']:
                fhir_observation = {
                    'resourceType': 'Observation',
                    'id': obs_data.get('ObservationID', ''),
                    'status': 'final',
                    'code': {
                        'coding': [
                            {
                                'system': 'http://epic.com/observation-codes',
                                'code': obs_data.get('Code', ''),
                                'display': obs_data.get('Description', '')
                            }
                        ]
                    },
                    'subject': {'reference': f'Patient/{patient_id}'},
                    'effectiveDateTime': cls._parse_datetime(obs_data.get('Date', '')),
                    'valueQuantity': {
                        'value': obs_data.get('Value', 0),
                        'unit': obs_data.get('Unit', ''),
                        'system': 'http://unitsofmeasure.org'
                    }
                }
                resources.append(fhir_observation)
        
        # Transform Epic Medications
        if 'Medications' in epic_data:
            for med_data in epic_data['Medications']:
                fhir_medication = {
                    'resourceType': 'MedicationStatement',
                    'id': med_data.get('MedicationID', ''),
                    'status': 'active',
                    'medicationCodeableConcept': {
                        'coding': [
                            {
                                'system': 'http://www.nlm.nih.gov/research/umls/rxnorm',
                                'code': med_data.get('RxNormCode', ''),
                                'display': med_data.get('MedicationName', '')
                            }
                        ]
                    },
                    'subject': {'reference': f'Patient/{patient_id}'},
                    'effectiveDateTime': cls._parse_datetime(med_data.get('StartDate', '')),
                    'dosage': [
                        {
                            'text': med_data.get('Instructions', ''),
                            'doseAndRate': [
                                {
                                    'doseQuantity': {
                                        'value': med_data.get('Dose', 0),
                                        'unit': med_data.get('DoseUnit', '')
                                    }
                                }
                            ]
                        }
                    ]
                }
                resources.append(fhir_medication)
        
        # Transform Epic Conditions/Diagnoses
        if 'Conditions' in epic_data:
            for cond_data in epic_data['Conditions']:
                fhir_condition = {
                    'resourceType': 'Condition',
                    'id': cond_data.get('ConditionID', ''),
                    'clinicalStatus': {
                        'coding': [
                            {
                                'system': 'http://terminology.hl7.org/CodeSystem/condition-clinical',
                                'code': 'active'
                            }
                        ]
                    },
                    'code': {
                        'coding': [
                            {
                                'system': 'http://hl7.org/fhir/sid/icd-10',
                                'code': cond_data.get('ICD10Code', ''),
                                'display': cond_data.get('Description', '')
                            }
                        ]
                    },
                    'subject': {'reference': f'Patient/{patient_id}'},
                    'onsetDateTime': cls._parse_datetime(cond_data.get('OnsetDate', ''))
                }
                
                # Add rare disease specific extensions
                if cls._is_rare_disease(cond_data.get('ICD10Code', '')):
                    fhir_condition['extension'] = [
                        {
                            'url': 'http://klararety.com/fhir/StructureDefinition/rare-disease-indicator',
                            'valueBoolean': True
                        }
                    ]
                
                resources.append(fhir_condition)
        
        return resources
    
    @classmethod
    def _transform_cerner_data(cls, cerner_data: Dict[str, Any], patient_id: str) -> List[Dict[str, Any]]:
        """Transform Cerner EHR data to FHIR format."""
        # Similar transformation logic for Cerner's data format
        resources = []
        
        # Cerner typically returns FHIR-compliant data, so less transformation needed
        if 'entry' in cerner_data:
            for entry in cerner_data['entry']:
                if 'resource' in entry:
                    resource = entry['resource']
                    # Update patient references to use our patient ID
                    cls._update_patient_references(resource, patient_id)
                    resources.append(resource)
        
        return resources
    
    @classmethod
    def _transform_generic_data(cls, data: Dict[str, Any], patient_id: str) -> List[Dict[str, Any]]:
        """Generic transformation for unknown external systems."""
        resources = []
        
        # Try to detect common patterns and transform accordingly
        if 'patient' in data or 'Patient' in data:
            # Handle patient data
            patient_info = data.get('patient', data.get('Patient', {}))
            # Basic patient transformation
            pass
        
        if 'records' in data:
            # Handle generic medical records
            for record in data['records']:
                # Transform based on record type
                if record.get('type') == 'medication':
                    # Transform to MedicationStatement
                    pass
                elif record.get('type') == 'condition':
                    # Transform to Condition
                    pass
                elif record.get('type') == 'observation':
                    # Transform to Observation
                    pass
        
        return resources
    
    @classmethod
    def _is_rare_disease(cls, icd10_code: str) -> bool:
        """Check if an ICD-10 code represents a rare disease."""
        # Define rare disease ICD-10 code patterns
        rare_disease_patterns = [
            'Q', # Congenital malformations
            'E70', 'E71', 'E72', 'E74', 'E75', 'E76', 'E77', 'E78', 'E79', # Metabolic disorders
            'G71', # Primary disorders of muscles
            'G37', # Other demyelinating diseases
            'D81', 'D82', 'D83', 'D84', # Immunodeficiencies
        ]
        
        for pattern in rare_disease_patterns:
            if icd10_code.startswith(pattern):
                return True
        
        return False
    
    @classmethod
    def _update_patient_references(cls, resource: Dict[str, Any], patient_id: str):
        """Update patient references in FHIR resource to use our patient ID."""
        if 'subject' in resource and 'reference' in resource['subject']:
            resource['subject']['reference'] = f'Patient/{patient_id}'
        
        if 'patient' in resource and 'reference' in resource['patient']:
            resource['patient']['reference'] = f'Patient/{patient_id}'
    
    @classmethod
    def _parse_date(cls, date_str: str) -> Optional[str]:
        """Parse date string to FHIR date format."""
        if not date_str:
            return None
        
        try:
            # Try common date formats
            for fmt in ['%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y']:
                try:
                    date_obj = datetime.strptime(date_str, fmt)
                    return date_obj.strftime('%Y-%m-%d')
                except ValueError:
                    continue
        except Exception:
            pass
        
        return None
    
    @classmethod
    def _parse_datetime(cls, datetime_str: str) -> Optional[str]:
        """Parse datetime string to FHIR datetime format."""
        if not datetime_str:
            return None
        
        try:
            # Try common datetime formats
            for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%m/%d/%Y %H:%M']:
                try:
                    dt_obj = datetime.strptime(datetime_str, fmt)
                    return dt_obj.strftime('%Y-%m-%dT%H:%M:%S')
                except ValueError:
                    continue
        except Exception:
            pass
        
        return None
    
    @classmethod
    def _map_gender(cls, gender_str: str) -> str:
        """Map gender string to FHIR gender code."""
        gender_mapping = {
            'M': 'male',
            'F': 'female',
            'MALE': 'male',
            'FEMALE': 'female',
            'OTHER': 'other',
            'UNKNOWN': 'unknown'
        }
        
        return gender_mapping.get(gender_str.upper(), 'unknown')

