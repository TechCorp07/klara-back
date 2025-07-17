# fhir/tasks.py
from celery import shared_task
from django.utils import timezone
from django.contrib.auth import get_user_model
import logging

User = get_user_model()
logger = logging.getLogger(__name__)

@shared_task
def retrieve_patient_data_from_external_system(request_id, patient_id, system_name, data_types, date_range_start, date_range_end):
    """Retrieve patient data from external EHR system."""
    from .services.external_integration import ExternalEHRService
    
    try:
        service = ExternalEHRService()
        result = service.retrieve_patient_data(
            system_name=system_name,
            patient_id=patient_id,
            data_types=data_types,
            date_range_start=date_range_start,
            date_range_end=date_range_end
        )
        
        # Transform and store the data
        from .services.data_transformation import DataTransformationService
        
        if result['success']:
            transformation_result = DataTransformationService.transform_external_to_fhir(
                external_data=result['data'],
                system_name=system_name,
                patient_id=patient_id
            )
            
            # Store FHIR resources
            if transformation_result['success']:
                for resource in transformation_result['resources']:
                    # Save to appropriate FHIR model
                    pass
        
        return result
        
    except Exception as e:
        logger.error(f"Error retrieving data from {system_name}: {str(e)}")
        return {'success': False, 'error': str(e)}

@shared_task
def process_bulk_export(export_id):
    """Process FHIR bulk export job."""
    from .services.bulk_export import BulkDataExportService
    
    return BulkDataExportService.process_export(export_id)

@shared_task
def retrieve_family_member_data(request_id, family_member_info, requesting_patient_id):
    """Retrieve family member medical data for genetic analysis."""
    from .models.data_requests import FamilyHistoryRequest
    from .services.external_integration import ExternalEHRService
    
    try:
        # Get the family history request
        family_request = FamilyHistoryRequest.objects.get(request_id=request_id)
        
        # This would typically involve:
        # 1. Contacting family member's healthcare provider
        # 2. Requesting consent from family member
        # 3. Retrieving authorized data
        
        # For now, we'll simulate the process
        family_member = family_member_info
        relationship = family_member.get('relationship', 'unknown')
        
        # Simulate data retrieval process
        result = {
            'success': True,
            'family_member': relationship,
            'requesting_patient_id': requesting_patient_id,
            'data_retrieved': [],
            'consent_status': 'pending',
            'message': f'Family history request initiated for {relationship}'
        }
        
        # In a real implementation, you would:
        # 1. Send consent requests to family members
        # 2. Retrieve data from their EHR systems once consent is granted
        # 3. Transform the data to FHIR format
        # 4. Store the family history data
        
        logger.info(f"Family member data request processed for {relationship}")
        return result
        
    except Exception as e:
        logger.error(f"Error retrieving family member data: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'family_member': family_member_info.get('relationship', 'unknown')
        }

@shared_task
def retrieve_patient_data_from_integration(request_id, integration_id, data_types, date_range_start, date_range_end):
    """Retrieve patient data from connected EHR integration."""
    from healthcare.models import EHRIntegration
    from .services.data_transformation import DataTransformationService
    
    logger = logging.getLogger(__name__)
    
    try:
        # Get the EHR integration
        integration = EHRIntegration.objects.get(id=integration_id)
        
        if integration.status != 'active':
            return {
                'success': False,
                'error': 'Integration is not active',
                'integration_type': integration.integration_type
            }
        
        # Retrieve data based on integration type
        if integration.integration_type == 'epic':
            result = _retrieve_from_epic(integration, data_types, date_range_start, date_range_end)
        elif integration.integration_type == 'cerner':
            result = _retrieve_from_cerner(integration, data_types, date_range_start, date_range_end)
        elif integration.integration_type == 'allscripts':
            result = _retrieve_from_allscripts(integration, data_types, date_range_start, date_range_end)
        else:
            result = _retrieve_from_generic_ehr(integration, data_types, date_range_start, date_range_end)
        
        if result['success']:
            # Transform external data to FHIR format
            transformation_result = DataTransformationService.transform_external_to_fhir(
                external_data=result['data'],
                system_name=integration.integration_type,
                patient_id=str(integration.patient.id)
            )
            
            if transformation_result['success']:
                # Store FHIR resources
                stored_count = _store_fhir_resources(
                    transformation_result['resources'],
                    integration.patient
                )
                
                result['fhir_resources_stored'] = stored_count
        
        # Update integration last_sync timestamp
        integration.last_sync = timezone.now()
        integration.save(update_fields=['last_sync'])
        
        return result
        
    except EHRIntegration.DoesNotExist:
        return {
            'success': False,
            'error': 'EHR integration not found'
        }
    except Exception as e:
        logger.error(f"Error retrieving data from integration {integration_id}: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def _retrieve_from_epic(integration, data_types, date_range_start, date_range_end):
    """Retrieve data from Epic EHR system."""
    try:
        # This would use Epic's FHIR API
        # For now, return simulated data
        
        simulated_data = {
            'Patient': {
                'PatientID': integration.external_id,
                'FirstName': integration.patient.first_name,
                'LastName': integration.patient.last_name,
                'Gender': 'Unknown',
                'DateOfBirth': integration.patient.date_of_birth.isoformat() if integration.patient.date_of_birth else None
            },
            'Observations': [],
            'Medications': [],
            'Conditions': []
        }
        
        # Add sample data based on requested types
        if 'observations' in data_types or 'all' in data_types:
            simulated_data['Observations'] = [
                {
                    'ObservationID': 'epic-obs-001',
                    'Code': 'vital-signs',
                    'Description': 'Vital Signs',
                    'Value': 120,
                    'Unit': 'mmHg',
                    'Date': timezone.now().isoformat()
                }
            ]
        
        return {
            'success': True,
            'data': simulated_data,
            'system': 'epic',
            'records_retrieved': len(simulated_data['Observations']) + len(simulated_data['Medications']) + len(simulated_data['Conditions'])
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'system': 'epic'
        }

def _retrieve_from_cerner(integration, data_types, date_range_start, date_range_end):
    """Retrieve data from Cerner EHR system."""
    try:
        # This would use Cerner's FHIR API
        # Cerner typically returns FHIR-compliant data
        
        simulated_fhir_bundle = {
            'resourceType': 'Bundle',
            'type': 'collection',
            'entry': [
                {
                    'resource': {
                        'resourceType': 'Patient',
                        'id': integration.external_id,
                        'name': [
                            {
                                'family': integration.patient.last_name,
                                'given': [integration.patient.first_name]
                            }
                        ]
                    }
                }
            ]
        }
        
        return {
            'success': True,
            'data': simulated_fhir_bundle,
            'system': 'cerner',
            'records_retrieved': len(simulated_fhir_bundle['entry'])
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'system': 'cerner'
        }

def _retrieve_from_allscripts(integration, data_types, date_range_start, date_range_end):
    """Retrieve data from Allscripts EHR system."""
    try:
        # This would use Allscripts API
        # Return simulated data for now
        
        return {
            'success': True,
            'data': {'records': []},
            'system': 'allscripts',
            'records_retrieved': 0
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'system': 'allscripts'
        }

def _retrieve_from_generic_ehr(integration, data_types, date_range_start, date_range_end):
    """Retrieve data from generic EHR system."""
    try:
        # Generic EHR data retrieval
        return {
            'success': True,
            'data': {'records': []},
            'system': integration.integration_type,
            'records_retrieved': 0
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'system': integration.integration_type
        }

def _store_fhir_resources(resources, patient):
    """Store FHIR resources in the database."""
    from ..models import FHIRPatient, FHIRObservation, FHIRCondition, FHIRMedicationStatement
    
    stored_count = 0
    
    try:
        # Get or create FHIR patient
        fhir_patient, created = FHIRPatient.objects.get_or_create(
            id=patient.id,
            defaults={
                'identifier': patient.email,
                'family_name': patient.last_name,
                'given_name': patient.first_name,
                'gender': 'unknown',
                'birth_date': patient.date_of_birth
            }
        )
        
        for resource in resources:
            try:
                resource_type = resource.get('resourceType')
                
                if resource_type == 'Observation':
                    # Create FHIRObservation
                    FHIRObservation.objects.create(
                        patient=fhir_patient,
                        code=resource.get('code', {}).get('coding', [{}])[0].get('code', ''),
                        display=resource.get('code', {}).get('coding', [{}])[0].get('display', ''),
                        value_quantity=resource.get('valueQuantity', {}).get('value', 0),
                        unit=resource.get('valueQuantity', {}).get('unit', ''),
                        effective_date=resource.get('effectiveDateTime', timezone.now()),
                        status='final'
                    )
                    stored_count += 1
                    
                elif resource_type == 'Condition':
                    # Create FHIRCondition
                    FHIRCondition.objects.create(
                        patient=fhir_patient,
                        code=resource.get('code', {}).get('coding', [{}])[0].get('code', ''),
                        display=resource.get('code', {}).get('coding', [{}])[0].get('display', ''),
                        clinical_status='active',
                        onset_date=resource.get('onsetDateTime', timezone.now())
                    )
                    stored_count += 1
                    
                elif resource_type == 'MedicationStatement':
                    # Create FHIRMedicationStatement
                    FHIRMedicationStatement.objects.create(
                        patient=fhir_patient,
                        medication=resource.get('medicationCodeableConcept', {}).get('coding', [{}])[0].get('display', ''),
                        medication_code=resource.get('medicationCodeableConcept', {}).get('coding', [{}])[0].get('code', ''),
                        status='active',
                        effective_date=resource.get('effectiveDateTime', timezone.now())
                    )
                    stored_count += 1
                    
            except Exception as e:
                logger.error(f"Error storing FHIR resource: {str(e)}")
                continue
        
        return stored_count
        
    except Exception as e:
        logger.error(f"Error storing FHIR resources: {str(e)}")
        return 0
