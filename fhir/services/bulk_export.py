# fhir/services/bulk_export.py
import logging
import json
import gzip
import uuid
import os
from django.utils import timezone
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from datetime import timedelta
from typing import Dict, List, Any, Optional
from ..models import FHIRPatient, FHIRObservation, FHIRCondition, FHIRMedicationStatement

logger = logging.getLogger(__name__)

class BulkDataExportService:
    """
    FHIR Bulk Data Export API implementation.
    Supports sharing patient data with external healthcare institutions.
    """
    
    @classmethod
    def initiate_bulk_export(cls, requester, resource_types: List[str] = None, 
                           since: str = None, patient_ids: List[str] = None) -> Dict[str, Any]:
        """
        Initiate a bulk data export operation.
        
        Args:
            requester: User requesting the export
            resource_types: List of FHIR resource types to export
            since: Only include resources modified after this date
            patient_ids: Specific patient IDs to export (if authorized)
        """
        try:
            export_id = str(uuid.uuid4())
            
            # Default resource types for rare disease data
            if not resource_types:
                resource_types = [
                    'Patient', 'Observation', 'Condition', 'MedicationStatement',
                    'Encounter', 'Communication'
                ]
            
            # Create export job record
            export_job = BulkExportJob.objects.create(
                export_id=export_id,
                requester=requester,
                resource_types=resource_types,
                since_date=since,
                patient_ids=patient_ids or [],
                status='accepted',
                expires_at=timezone.now() + timedelta(hours=24)  # Export links expire in 24 hours
            )
            
            # Queue export processing
            from .tasks import process_bulk_export
            process_bulk_export.delay(export_id)
            
            return {
                'success': True,
                'export_id': export_id,
                'status': 'accepted',
                'message': 'Bulk export initiated'
            }
            
        except Exception as e:
            logger.error(f"Error initiating bulk export: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    @classmethod
    def process_export(cls, export_id: str) -> Dict[str, Any]:
        """Process the bulk export job."""
        try:
            export_job = BulkExportJob.objects.get(export_id=export_id)
            export_job.status = 'in-progress'
            export_job.started_at = timezone.now()
            export_job.save()
            
            # Create export directory
            export_dir = os.path.join(settings.MEDIA_ROOT, 'fhir_exports', export_id)
            os.makedirs(export_dir, exist_ok=True)
            
            export_files = []
            
            # Export each resource type
            for resource_type in export_job.resource_types:
                file_info = cls._export_resource_type(
                    resource_type, 
                    export_job.patient_ids,
                    export_job.since_date,
                    export_dir,
                    export_job.requester
                )
                
                if file_info:
                    export_files.append(file_info)
            
            # Update export job with results
            export_job.status = 'completed'
            export_job.completed_at = timezone.now()
            export_job.export_files = export_files
            export_job.total_resources = sum(f['count'] for f in export_files)
            export_job.save()
            
            return {
                'success': True,
                'export_id': export_id,
                'status': 'completed',
                'files': export_files
            }
            
        except Exception as e:
            logger.error(f"Error processing bulk export {export_id}: {str(e)}")
            
            # Update job status to failed
            try:
                export_job = BulkExportJob.objects.get(export_id=export_id)
                export_job.status = 'failed'
                export_job.error_message = str(e)
                export_job.save()
            except:
                pass
            
            return {
                'success': False,
                'error': str(e)
            }
    
    @classmethod
    def _export_resource_type(cls, resource_type: str, patient_ids: List[str], 
                            since_date: str, export_dir: str, requester) -> Optional[Dict[str, Any]]:
        """Export a specific FHIR resource type."""
        try:
            # Get model class for resource type
            model_map = {
                'Patient': FHIRPatient,
                'Observation': FHIRObservation,
                'Condition': FHIRCondition,
                'MedicationStatement': FHIRMedicationStatement,
            }
            
            model_class = model_map.get(resource_type)
            if not model_class:
                logger.warning(f"Unsupported resource type: {resource_type}")
                return None
            
            # Build query
            queryset = model_class.objects.all()
            
            # Filter by patient IDs if specified
            if patient_ids:
                if resource_type == 'Patient':
                    queryset = queryset.filter(id__in=patient_ids)
                else:
                    queryset = queryset.filter(patient__id__in=patient_ids)
            
            # Filter by date if specified
            if since_date:
                queryset = queryset.filter(updated_at__gte=since_date)
            
            # Apply permissions - only export data requester has access to
            if hasattr(model_class, 'filter_by_permissions'):
                queryset = model_class.filter_by_permissions(queryset, requester)
            
            # Export to NDJSON file
            filename = f"{resource_type}.ndjson"
            filepath = os.path.join(export_dir, filename)
            
            resource_count = 0
            
            with open(filepath, 'w') as f:
                for resource in queryset:
                    fhir_json = resource.to_fhir()
                    f.write(json.dumps(fhir_json) + '\n')
                    resource_count += 1
            
            # Compress the file
            compressed_filepath = filepath + '.gz'
            with open(filepath, 'rb') as f_in:
                with gzip.open(compressed_filepath, 'wb') as f_out:
                    f_out.writelines(f_in)
            
            # Remove uncompressed file
            os.remove(filepath)
            
            # Generate download URL
            download_url = f"/api/fhir/bulk-export/{export_job.export_id}/download/{resource_type}.ndjson.gz"
            
            return {
                'type': resource_type,
                'url': download_url,
                'count': resource_count,
                'filename': f"{resource_type}.ndjson.gz"
            }
            
        except Exception as e:
            logger.error(f"Error exporting {resource_type}: {str(e)}")
            return None

