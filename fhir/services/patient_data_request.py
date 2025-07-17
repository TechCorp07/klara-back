# fhir/services/patient_data_request.py
import logging
import uuid
from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import timedelta
from typing import Dict, List, Any, Optional
from fhir.models.data_requests import FamilyHistoryRequest, PatientDataRequest
from fhir.tasks import retrieve_family_member_data, retrieve_patient_data_from_integration
from ..models import FHIRPatient
from healthcare.models import EHRIntegration

User = get_user_model()
logger = logging.getLogger(__name__)

class PatientDataRequestService:
    """
    Service for handling patient requests for their historical medical data.
    Critical for rare disease patients who need comprehensive medical history.
    """
    
    @classmethod
    def initiate_data_request(cls, patient: User, provider: User, data_types: List[str], 
                            date_range_start: str = None, date_range_end: str = None,
                            external_systems: List[str] = None) -> Dict[str, Any]:
        """
        Initiate a patient data request from external EHR systems.
        
        Args:
            patient: Patient requesting data
            provider: Provider facilitating the request
            data_types: Types of data to request (medications, conditions, observations, etc.)
            date_range_start: Start date for data retrieval (ISO format)
            date_range_end: End date for data retrieval (ISO format)
            external_systems: List of external EHR systems to query
        """
        try:
            request_id = str(uuid.uuid4())
            
            # Create data request record
            data_request = PatientDataRequest.objects.create(
                request_id=request_id,
                patient=patient,
                requesting_provider=provider,
                data_types=data_types,
                date_range_start=date_range_start,
                date_range_end=date_range_end,
                external_systems=external_systems or [],
                status='initiated',
                consent_provided=True,  # Patient is making the request
                consent_date=timezone.now()
            )
            
            # Queue data retrieval tasks for each external system
            pending_requests = []
            
            if external_systems:
                for system in external_systems:
                    # Queue task to retrieve data from each system
                    from .tasks import retrieve_patient_data_from_external_system
                    
                    task_result = retrieve_patient_data_from_external_system.delay(
                        request_id=request_id,
                        patient_id=patient.id,
                        system_name=system,
                        data_types=data_types,
                        date_range_start=date_range_start,
                        date_range_end=date_range_end
                    )
                    
                    pending_requests.append({
                        'system': system,
                        'task_id': task_result.id,
                        'status': 'pending'
                    })
            
            # Also retrieve data from connected EHR integrations
            connected_integrations = EHRIntegration.objects.filter(
                patient=patient,
                status='active',
                consent_granted=True
            )
            
            for integration in connected_integrations:
                task_result = retrieve_patient_data_from_integration.delay(
                    request_id=request_id,
                    integration_id=integration.id,
                    data_types=data_types,
                    date_range_start=date_range_start,
                    date_range_end=date_range_end
                )
                
                pending_requests.append({
                    'system': integration.integration_type,
                    'task_id': task_result.id,
                    'status': 'pending'
                })
            
            # Update request with pending tasks
            data_request.pending_requests = pending_requests
            data_request.save()
            
            # Log the request for audit
            from audit.models import AuditEvent
            AuditEvent.objects.create(
                user=provider,
                event_type='DATA_REQUEST',
                resource_type='patient_data',
                resource_id=str(patient.id),
                description=f"Patient data request initiated for {patient.email}",
                additional_data={
                    'request_id': request_id,
                    'data_types': data_types,
                    'external_systems': external_systems
                }
            )
            
            return {
                'success': True,
                'request_id': request_id,
                'status': 'initiated',
                'message': f'Data request initiated for {len(pending_requests)} systems',
                'pending_requests': pending_requests
            }
            
        except Exception as e:
            logger.error(f"Error initiating patient data request: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to initiate data request'
            }
    
    @classmethod
    def request_family_history_data(cls, patient: User, provider: User, 
                                  family_members: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Request family history data for genetic conditions.
        Critical for rare disease diagnosis and treatment.
        """
        try:
            request_id = str(uuid.uuid4())
            
            # Create family history request
            family_request = FamilyHistoryRequest.objects.create(
                request_id=request_id,
                patient=patient,
                requesting_provider=provider,
                family_members_info=family_members,
                status='initiated',
                consent_provided=True,
                consent_date=timezone.now()
            )
            
            # For each family member, initiate data request if they have records
            family_data_requests = []
            
            for member in family_members:
                if member.get('has_medical_records', False):
                    # Queue task to retrieve family member data
                    task_result = retrieve_family_member_data.delay(
                        request_id=request_id,
                        family_member_info=member,
                        requesting_patient_id=patient.id
                    )
                    
                    family_data_requests.append({
                        'family_member': member.get('relationship'),
                        'task_id': task_result.id,
                        'status': 'pending'
                    })
            
            family_request.pending_requests = family_data_requests
            family_request.save()
            
            return {
                'success': True,
                'request_id': request_id,
                'family_requests': len(family_data_requests),
                'message': 'Family history data request initiated'
            }
            
        except Exception as e:
            logger.error(f"Error requesting family history data: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    @classmethod
    def get_request_status(cls, request_id: str) -> Dict[str, Any]:
        """Get status of a data request."""
        try:
            data_request = PatientDataRequest.objects.get(request_id=request_id)
            
            # Check status of pending requests
            completed_requests = []
            failed_requests = []
            still_pending = []
            
            for req in data_request.pending_requests:
                # Check Celery task status
                from celery.result import AsyncResult
                task = AsyncResult(req['task_id'])
                
                if task.state == 'SUCCESS':
                    completed_requests.append(req)
                elif task.state == 'FAILURE':
                    failed_requests.append(req)
                else:
                    still_pending.append(req)
            
            # Update overall status
            if not still_pending:
                if failed_requests:
                    data_request.status = 'partially_completed'
                else:
                    data_request.status = 'completed'
                data_request.completed_at = timezone.now()
                data_request.save()
            
            return {
                'request_id': request_id,
                'status': data_request.status,
                'total_requests': len(data_request.pending_requests),
                'completed': len(completed_requests),
                'failed': len(failed_requests),
                'pending': len(still_pending),
                'created_at': data_request.created_at,
                'completed_at': data_request.completed_at
            }
            
        except PatientDataRequest.DoesNotExist:
            return {'error': 'Request not found'}
        except Exception as e:
            logger.error(f"Error getting request status: {str(e)}")
            return {'error': str(e)}

