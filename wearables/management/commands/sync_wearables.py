import logging
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.contrib.auth import get_user_model
from wearables.models import WearableIntegration, SyncLog
from wearables.services import (
    withings_service, apple_health_service, google_fit_service,
    samsung_health_service, fitbit_service
)
from wearables.views import DataSyncViewSet

User = get_user_model()
logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Manually trigger synchronization of wearable device data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--user_id',
            type=int,
            help='Sync data only for the specified user ID',
        )
        
        parser.add_argument(
            '--username',
            type=str,
            help='Sync data only for the specified username',
        )
        
        parser.add_argument(
            '--integration_type',
            type=str,
            choices=dict(WearableIntegration.IntegrationType.choices).keys(),
            help='Sync data only for the specified integration type',
        )
        
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days to look back for data (default: 30)',
        )
        
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force sync even if not due based on frequency',
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be synced without actually syncing',
        )

    def handle(self, *args, **options):
        user_id = options.get('user_id')
        username = options.get('username')
        integration_type = options.get('integration_type')
        days = options.get('days', 30)
        force = options.get('force', False)
        dry_run = options.get('dry_run', False)
        
        # Build queryset for integrations
        integrations = WearableIntegration.objects.filter(
            status=WearableIntegration.ConnectionStatus.CONNECTED,
            consent_granted=True
        )
        
        # Apply filters if provided
        if user_id:
            integrations = integrations.filter(user_id=user_id)
            
        if username:
            integrations = integrations.filter(user__username=username)
            
        if integration_type:
            integrations = integrations.filter(integration_type=integration_type)
        
        if not integrations.exists():
            self.stdout.write(self.style.WARNING('No matching wearable integrations found.'))
            return
        
        self.stdout.write(f"Found {integrations.count()} matching integrations.")
        
        # Process each integration
        synced_count = 0
        skipped_count = 0
        error_count = 0
        
        for integration in integrations:
            integration_name = f"{integration.get_integration_type_display()} for {integration.user.username}"
            
            # Check if sync is due based on frequency
            if not force and not integration.needs_sync():
                hours_since_sync = 0
                if integration.last_sync:
                    hours_since_sync = (timezone.now() - integration.last_sync).total_seconds() / 3600
                
                self.stdout.write(
                    self.style.NOTICE(f"Skipping {integration_name} - last synced {hours_since_sync:.1f} hours ago.")
                )
                skipped_count += 1
                continue
            
            self.stdout.write(f"Processing {integration_name}...")
            
            if dry_run:
                self.stdout.write(self.style.SUCCESS(f"Would sync {integration_name} (dry run)"))
                synced_count += 1
                continue
            
            # Calculate date range for sync
            end_date = timezone.now()
            start_date = end_date - timedelta(days=days)
            
            try:
                # Create sync log
                sync_log = SyncLog.objects.create(
                    user=integration.user,
                    integration_type=integration.integration_type,
                    status=SyncLog.SyncStatus.FAILED,  # Default to failed, update on success
                    start_time=timezone.now(),
                    end_time=timezone.now(),  # Will be updated when complete
                    data_start_date=start_date,
                    data_end_date=end_date
                )
                
                # Initialize a DataSyncViewSet to use its methods
                sync_view = DataSyncViewSet()
                
                # Sync based on integration type
                if integration.integration_type == 'withings':
                    results = sync_view._sync_withings_data(integration, start_date, end_date)
                elif integration.integration_type == 'fitbit':
                    results = sync_view._sync_fitbit_data(integration, start_date, end_date)
                elif integration.integration_type == 'google_fit':
                    results = sync_view._sync_google_fit_data(integration, start_date, end_date)
                else:
                    sync_log.status = SyncLog.SyncStatus.SKIPPED
                    sync_log.error_message = f"Sync for {integration.integration_type} not implemented in command"
                    sync_log.end_time = timezone.now()
                    sync_log.save()
                    
                    self.stdout.write(
                        self.style.WARNING(f"Skipping {integration_name} - sync method not implemented in command")
                    )
                    skipped_count += 1
                    continue
                
                # Update integration last_sync timestamp
                integration.last_sync = timezone.now()
                integration.save(update_fields=['last_sync'])
                
                # Update sync log
                sync_log.status = SyncLog.SyncStatus.SUCCESS
                sync_log.measurements_synced = results.get('measurements_synced', 0)
                sync_log.details = {
                    'data_types': results.get('data_types_synced', []),
                    'message': results.get('message', '')
                }
                sync_log.end_time = timezone.now()
                sync_log.save()
                
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Synced {results.get('measurements_synced', 0)} measurements for {integration_name}"
                    )
                )
                synced_count += 1
                
            except Exception as e:
                logger.error(f"Error syncing {integration_name}: {str(e)}")
                
                # Update sync log with error
                if 'sync_log' in locals():
                    sync_log.status = SyncLog.SyncStatus.FAILED
                    sync_log.error_message = str(e)
                    sync_log.end_time = timezone.now()
                    sync_log.save()
                
                self.stdout.write(
                    self.style.ERROR(f"Error syncing {integration_name}: {str(e)}")
                )
                error_count += 1
        
        # Summary
        self.stdout.write("\nSync Summary:")
        self.stdout.write(f"  Synced: {synced_count}")
        self.stdout.write(f"  Skipped: {skipped_count}")
        self.stdout.write(f"  Errors: {error_count}")
        self.stdout.write(f"  Total: {synced_count + skipped_count + error_count}")
