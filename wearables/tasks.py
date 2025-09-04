from __future__ import absolute_import, unicode_literals
from celery import shared_task
import logging
import traceback
from datetime import timedelta
from django.utils import timezone
from __future__ import absolute_import, unicode_literals

from .models import WearableIntegration, SyncLog
from .services import (
    withings_service, fitbit_service, google_fit_service
)

logger = logging.getLogger(__name__)

@shared_task
def sync_wearable_data_for_all_users():
    """
    Task to sync data from all connected wearable integrations.
    This task will find all integrations that are due for sync and
    trigger the appropriate sync task for each one.
    """
    logger.info("Starting wearable data sync for all users")
    
    # Get integrations due for sync
    integrations = WearableIntegration.objects.filter(
        status=WearableIntegration.ConnectionStatus.CONNECTED,
        consent_granted=True
    )
    
    pending_syncs = []
    for integration in integrations:
        # Check if sync is due based on sync frequency
        if not integration.last_sync or integration.needs_sync():
            pending_syncs.append(integration)
    
    logger.info(f"Found {len(pending_syncs)} integrations due for sync")
    
    # Trigger sync for each integration
    success_count = 0
    failure_count = 0
    
    for integration in pending_syncs:
        try:
            # Call the appropriate sync task based on integration type
            if integration.integration_type == 'withings':
                sync_withings_data.delay(integration.id)
            elif integration.integration_type == 'fitbit':
                sync_fitbit_data.delay(integration.id)
            elif integration.integration_type == 'google_fit':
                sync_google_fit_data.delay(integration.id)
            else:
                logger.info(f"Skipping {integration.integration_type} for user {integration.user.username} - no sync task")
                continue
                
            success_count += 1
        except Exception as e:
            logger.error(f"Error scheduling sync for {integration.integration_type} "
                        f"(user {integration.user.username}): {str(e)}")
            failure_count += 1
    
    summary = f"Sync scheduling complete: {success_count} scheduled, {failure_count} failed"
    logger.info(summary)
    return summary

@shared_task
def sync_withings_data(integration_id):
    """Sync data from Withings for a specific integration."""
    logger.info(f"Starting Withings data sync for integration {integration_id}")
    
    try:
        # Get the integration
        integration = WearableIntegration.objects.get(
            id=integration_id,
            integration_type='withings'
        )
        
        # Skip if no consent or not connected
        if not integration.consent_granted or not integration.is_connected():
            logger.warning(f"Skipping Withings sync for user {integration.user.username} - "
                          f"Consent: {integration.consent_granted}, Connected: {integration.is_connected()}")
            return "Skipped - no consent or not connected"
        
        # Calculate date range - last sync date or 30 days ago
        end_date = timezone.now()
        if integration.last_sync:
            # Start from last sync
            start_date = integration.last_sync - timedelta(days=1)  # Overlap by 1 day
        else:
            # Start from 30 days ago for first sync
            start_date = end_date - timedelta(days=30)
        
        # Create sync log
        sync_log = SyncLog.objects.create(
            user=integration.user,
            integration_type='withings',
            status=SyncLog.SyncStatus.FAILED,  # Default to failed, update on success
            start_time=timezone.now(),
            end_time=timezone.now(),  # Will be updated when complete
            data_start_date=start_date,
            data_end_date=end_date
        )
        
        # Initialize a DataSyncViewSet to use its methods
        from .views import DataSyncViewSet
        sync_view = DataSyncViewSet()
        
        # Convert dates to timestamps for Withings API
        start_timestamp = int(start_date.timestamp())
        end_timestamp = int(end_date.timestamp())
        
        # Refresh token if needed
        if integration.token_expiry <= timezone.now():
            success = withings_service.refresh_token(integration)
            if not success:
                integration.status = WearableIntegration.ConnectionStatus.EXPIRED
                integration.save(update_fields=['status'])
                
                sync_log.status = SyncLog.SyncStatus.FAILED
                sync_log.error_message = "Token refresh failed"
                sync_log.end_time = timezone.now()
                sync_log.save()
                
                return "Failed - token refresh error"
        
        # Perform the sync
        sync_results = sync_view._sync_withings_data(integration, start_date, end_date)
        
        # Update integration last_sync timestamp
        integration.last_sync = timezone.now()
        integration.save(update_fields=['last_sync'])
        
        # Update sync log
        sync_log.status = SyncLog.SyncStatus.SUCCESS
        sync_log.measurements_synced = sync_results.get('measurements_synced', 0)
        sync_log.details = {
            'data_types': sync_results.get('data_types_synced', []),
            'message': sync_results.get('message', '')
        }
        sync_log.end_time = timezone.now()
        sync_log.save()
        
        return f"Success - synced {sync_results.get('measurements_synced', 0)} measurements"
    
    except Exception as e:
        logger.error(f"Error in Withings sync task: {str(e)}")
        logger.error(traceback.format_exc())
        
        try:
            # Try to update the sync log
            sync_log = SyncLog.objects.get(
                user_id=WearableIntegration.objects.get(id=integration_id).user_id,
                integration_type='withings',
                status=SyncLog.SyncStatus.FAILED
            )
            
            sync_log.error_message = str(e)
            sync_log.end_time = timezone.now()
            sync_log.details = {
                'error': str(e),
                'traceback': traceback.format_exc()
            }
            sync_log.save()
        except:
            # If that fails, just log it
            logger.error("Failed to update sync log")
        
        return f"Failed - {str(e)}"

@shared_task
def sync_fitbit_data(integration_id):
    """Sync data from Fitbit for a specific integration."""
    logger.info(f"Starting Fitbit data sync for integration {integration_id}")
    
    try:
        # Get the integration
        integration = WearableIntegration.objects.get(
            id=integration_id,
            integration_type='fitbit'
        )
        
        # Skip if no consent or not connected
        if not integration.consent_granted or not integration.is_connected():
            logger.warning(f"Skipping Fitbit sync for user {integration.user.username} - "
                          f"Consent: {integration.consent_granted}, Connected: {integration.is_connected()}")
            return "Skipped - no consent or not connected"
        
        # Calculate date range - last sync date or 30 days ago
        end_date = timezone.now()
        if integration.last_sync:
            # Start from last sync
            start_date = integration.last_sync - timedelta(days=1)  # Overlap by 1 day
        else:
            # Start from 30 days ago for first sync
            start_date = end_date - timedelta(days=30)
        
        # Create sync log
        sync_log = SyncLog.objects.create(
            user=integration.user,
            integration_type='fitbit',
            status=SyncLog.SyncStatus.FAILED,  # Default to failed, update on success
            start_time=timezone.now(),
            end_time=timezone.now(),  # Will be updated when complete
            data_start_date=start_date,
            data_end_date=end_date
        )
        
        # Refresh token if needed
        if integration.token_expiry <= timezone.now():
            success = fitbit_service.refresh_token(integration)
            if not success:
                integration.status = WearableIntegration.ConnectionStatus.EXPIRED
                integration.save(update_fields=['status'])
                
                sync_log.status = SyncLog.SyncStatus.FAILED
                sync_log.error_message = "Token refresh failed"
                sync_log.end_time = timezone.now()
                sync_log.save()
                
                return "Failed - token refresh error"
        
        # Perform the sync - this would be implemented in a future update
        # For now, just update the sync log
        
        sync_log.status = SyncLog.SyncStatus.SKIPPED
        sync_log.error_message = "Fitbit sync not yet implemented"
        sync_log.end_time = timezone.now()
        sync_log.save()
        
        return "Skipped - Fitbit sync not yet implemented"
    
    except Exception as e:
        logger.error(f"Error in Fitbit sync task: {str(e)}")
        logger.error(traceback.format_exc())
        
        try:
            # Try to update the sync log
            sync_log = SyncLog.objects.get(
                user_id=WearableIntegration.objects.get(id=integration_id).user_id,
                integration_type='fitbit',
                status=SyncLog.SyncStatus.FAILED
            )
            
            sync_log.error_message = str(e)
            sync_log.end_time = timezone.now()
            sync_log.details = {
                'error': str(e),
                'traceback': traceback.format_exc()
            }
            sync_log.save()
        except:
            # If that fails, just log it
            logger.error("Failed to update sync log")
        
        return f"Failed - {str(e)}"

@shared_task
def sync_google_fit_data(integration_id):
    """Sync data from Google Fit for a specific integration."""
    logger.info(f"Starting Google Fit data sync for integration {integration_id}")
    
    try:
        # Get the integration
        integration = WearableIntegration.objects.get(
            id=integration_id,
            integration_type='google_fit'
        )
        
        # Skip if no consent or not connected
        if not integration.consent_granted or not integration.is_connected():
            logger.warning(f"Skipping Google Fit sync for user {integration.user.username} - "
                          f"Consent: {integration.consent_granted}, Connected: {integration.is_connected()}")
            return "Skipped - no consent or not connected"
        
        # Calculate date range - last sync date or 30 days ago
        end_date = timezone.now()
        if integration.last_sync:
            # Start from last sync
            start_date = integration.last_sync - timedelta(days=1)  # Overlap by 1 day
        else:
            # Start from 30 days ago for first sync
            start_date = end_date - timedelta(days=30)
        
        # Create sync log
        sync_log = SyncLog.objects.create(
            user=integration.user,
            integration_type='google_fit',
            status=SyncLog.SyncStatus.FAILED,  # Default to failed, update on success
            start_time=timezone.now(),
            end_time=timezone.now(),  # Will be updated when complete
            data_start_date=start_date,
            data_end_date=end_date
        )
        
        # Refresh token if needed
        if integration.token_expiry <= timezone.now():
            success = google_fit_service.refresh_token(integration)
            if not success:
                integration.status = WearableIntegration.ConnectionStatus.EXPIRED
                integration.save(update_fields=['status'])
                
                sync_log.status = SyncLog.SyncStatus.FAILED
                sync_log.error_message = "Token refresh failed"
                sync_log.end_time = timezone.now()
                sync_log.save()
                
                return "Failed - token refresh error"
        
        # Perform the sync - this would be implemented in a future update
        # For now, just update the sync log
        
        sync_log.status = SyncLog.SyncStatus.SKIPPED
        sync_log.error_message = "Google Fit sync not yet implemented"
        sync_log.end_time = timezone.now()
        sync_log.save()
        
        return "Skipped - Google Fit sync not yet implemented"
    
    except Exception as e:
        logger.error(f"Error in Google Fit sync task: {str(e)}")
        logger.error(traceback.format_exc())
        
        try:
            # Try to update the sync log
            sync_log = SyncLog.objects.get(
                user_id=WearableIntegration.objects.get(id=integration_id).user_id,
                integration_type='google_fit',
                status=SyncLog.SyncStatus.FAILED
            )
            
            sync_log.error_message = str(e)
            sync_log.end_time = timezone.now()
            sync_log.details = {
                'error': str(e),
                'traceback': traceback.format_exc()
            }
            sync_log.save()
        except:
            # If that fails, just log it
            logger.error("Failed to update sync log")
        
        return f"Failed - {str(e)}"

@shared_task
def cleanup_old_wearable_data(days_to_keep=90):
    """Clean up old wearable measurements data."""
    from .models import WearableMeasurement
    
    cutoff = timezone.now() - timezone.timedelta(days=days_to_keep)
    old_count = WearableMeasurement.objects.filter(measured_at__lt=cutoff).count()
    WearableMeasurement.objects.filter(measured_at__lt=cutoff).delete()

    logger.info(f"Deleted {old_count} old wearable measurements")
    return f"Deleted {old_count} records"

@shared_task
def fetch_withings_data_for_all_users():
    """Legacy task for backward compatibility."""
    logger.info("Starting legacy Withings data fetch for all users")
    
    # Find all Withings integrations
    withings_integrations = WearableIntegration.objects.filter(
        integration_type='withings',
        status=WearableIntegration.ConnectionStatus.CONNECTED,
        consent_granted=True
    )
    
    success_count = 0
    failure_count = 0
    
    for integration in withings_integrations:
        try:
            # Schedule sync task
            sync_withings_data.delay(integration.id)
            success_count += 1
        except Exception as e:
            logger.error(f"Error scheduling Withings sync for user {integration.user.username}: {str(e)}")
            failure_count += 1
    
    summary = f"Legacy task complete: {success_count} syncs scheduled, {failure_count} failed"
    logger.info(summary)
    return summary

@shared_task
def monitor_all_patients_adherence():
    """Monitor medication adherence for all patients with active wearables."""
    from .services.adherence_monitoring import AdherenceMonitoringService
    from medication.models import Medication
    from django.contrib.auth import get_user_model
    
    User = get_user_model()
    
    # Get patients with active medications and wearable integrations
    patients = User.objects.filter(
        role='patient',
        wearables_integrations__status='connected',
        medications__active=True
    ).distinct()
    
    monitored_count = 0
    
    for patient in patients:
        try:
            # Monitor each active medication
            active_medications = patient.medications.filter(active=True)
            
            for medication in active_medications:
                report = AdherenceMonitoringService.monitor_medication_adherence(patient, medication)
                if report.get('success'):
                    monitored_count += 1
                    
        except Exception as e:
            logger.error(f"Error monitoring adherence for patient {patient.id}: {str(e)}")
    
    logger.info(f"Monitored adherence for {monitored_count} medication instances")
    return f"Monitored adherence for {monitored_count} medication instances"

@shared_task
def sync_wearable_data_for_pharma():
    """Sync wearable data for pharmaceutical company research."""
    from .models import WearableIntegration, PharmaceuticalDataExport
    
    # Get pending exports
    pending_exports = PharmaceuticalDataExport.objects.filter(
        status=PharmaceuticalDataExport.ExportStatus.PENDING
    )
    
    for export in pending_exports:
        try:
            process_pharmaceutical_export.delay(export.id)
        except Exception as e:
            logger.error(f"Error queuing export {export.id}: {str(e)}")

@shared_task
def process_pharmaceutical_export(export_id):
    """Process data export for pharmaceutical company."""
    from .models import PharmaceuticalDataExport, WearableMeasurement
    import csv
    import os
    from django.conf import settings
    
    try:
        export = PharmaceuticalDataExport.objects.get(id=export_id)
        export.status = PharmaceuticalDataExport.ExportStatus.IN_PROGRESS
        export.started_at = timezone.now()
        export.save()
        
        # Create export file
        export_filename = f"pharma_export_{export_id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.csv"
        export_path = os.path.join(settings.MEDIA_ROOT, 'pharma_exports', export_filename)
        os.makedirs(os.path.dirname(export_path), exist_ok=True)
        
        # Get consented patients data
        patients = export.patients.filter(
            patient_profile__protocol_adherence_monitoring=True
        )
        
        records_exported = 0
        
        with open(export_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write headers
            headers = [
                'patient_id_hash', 'measurement_type', 'value', 'unit', 
                'measured_at', 'device_type', 'medication_protocol'
            ]
            writer.writerow(headers)
            
            # Export data for each patient
            for patient in patients:
                measurements = WearableMeasurement.objects.filter(
                    user=patient,
                    measured_at__gte=export.date_range_start,
                    measured_at__lte=export.date_range_end
                )
                
                if export.data_types:
                    measurements = measurements.filter(measurement_type__in=export.data_types)
                
                for measurement in measurements:
                    # Anonymize patient ID
                    patient_hash = hashlib.sha256(f"{patient.id}_{export.id}".encode()).hexdigest()[:16]
                    
                    writer.writerow([
                        patient_hash,
                        measurement.measurement_type,
                        measurement.value,
                        measurement.unit,
                        measurement.measured_at.isoformat(),
                        measurement.integration_type,
                        ','.join(patient.patient_profile.custom_drug_protocols or [])
                    ])
                    
                    records_exported += 1
        
        # Update export record
        export.status = PharmaceuticalDataExport.ExportStatus.COMPLETED
        export.completed_at = timezone.now()
        export.records_exported = records_exported
        export.file_path = export_path
        export.file_size = os.path.getsize(export_path)
        export.save()
        
        logger.info(f"Completed pharmaceutical export {export_id}: {records_exported} records")
        return f"Exported {records_exported} records"
        
    except Exception as e:
        export.status = PharmaceuticalDataExport.ExportStatus.FAILED
        export.save()
        logger.error(f"Error processing pharmaceutical export {export_id}: {str(e)}")
        return f"Export failed: {str(e)}"

@shared_task  
def sync_all_samsung_health():
    """Add Samsung to existing sync tasks."""
    from .models import WearableIntegration
    
    # Find existing sync scheduler and add Samsung
    samsung_integrations = WearableIntegration.objects.filter(
        integration_type='samsung_health',
        status='connected',
        consent_granted=True
    )
    
    for integration in samsung_integrations:
        try:
            # Use existing sync pattern
            sync_samsung_health_data.delay(integration.id)
        except Exception as e:
            logger.error(f"Failed to schedule Samsung sync: {str(e)}")

@shared_task
def sync_samsung_health_data(integration_id):
    """Individual Samsung sync task."""
    try:
        integration = WearableIntegration.objects.get(id=integration_id)
        
        # For now, just update last_sync since data comes via app
        integration.last_sync = timezone.now()
        integration.save()
        
        return "Samsung sync completed"
    except Exception as e:
        logger.error(f"Samsung sync failed: {str(e)}")
        return f"Failed: {str(e)}"
