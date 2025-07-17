import csv
import io
import json
import logging
import os
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Q
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
from ..models import (
    AuditEvent, PHIAccessLog, SecurityAuditLog, 
    ComplianceReport, AuditExport
)
from ..utils import parse_date, sanitize_request_data

logger = logging.getLogger(__name__)


class ExportService:
    """Service for generating and managing audit data exports."""
    
    @staticmethod
    def generate_audit_export(export, filters=None):
        """
        Generate an audit events export based on filters.
        
        Args:
            export: AuditExport object
            filters: Dictionary of filters to apply
            
        Returns:
            str: File URL if successful, None otherwise
        """
        try:
            # Update status to processing
            export.update_status(AuditExport.Status.PROCESSING)
            
            # Use filters from export object if not provided
            if filters is None:
                filters = export.filters
            
            # Build the queryset with filters
            queryset = AuditEvent.objects.all().order_by('-timestamp')
            
            # Apply filters
            queryset = ExportService._apply_audit_filters(queryset, filters)
            
            # Generate CSV in memory
            csv_buffer = io.StringIO()
            writer = csv.writer(csv_buffer)
            
            # Write header
            writer.writerow([
                'ID', 'Timestamp', 'User', 'Event Type', 'Resource Type', 
                'Resource ID', 'Description', 'IP Address', 'User Agent'
            ])
            
            # Write data rows
            for event in queryset.iterator():  # Use iterator for efficiency with large datasets
                writer.writerow([
                    str(event.id),
                    event.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    event.user.username if event.user else 'Anonymous',
                    event.get_event_type_display(),
                    event.resource_type,
                    event.resource_id,
                    event.description,
                    event.ip_address,
                    event.user_agent
                ])
            
            # Save the file to storage
            file_path = ExportService._generate_safe_filepath(
                prefix='audit_exports/',
                filename=f"audit_export_{export.user.username}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )
            
            # Save to storage
            default_storage.save(file_path, ContentFile(csv_buffer.getvalue().encode('utf-8')))
            
            # Set the file URL
            file_url = ExportService._generate_file_url(file_path)
                
            # Update export status
            export.update_status(
                AuditExport.Status.COMPLETED, 
                file_url=file_url
            )
            
            # Log the successful export
            AuditEvent.objects.create(
                user=export.user,
                event_type=AuditEvent.EventType.EXPORT,
                resource_type='audit_events',
                resource_id='export',
                description=f"Generated audit events export with {queryset.count()} records"
            )
            
            return file_url
            
        except Exception as e:
            logger.error(f"Error generating audit export: {str(e)}")
            
            # Update export with error status
            export.update_status(
                AuditExport.Status.FAILED,
                error_message=str(e)
            )
            
            return None
    
    @staticmethod
    def generate_phi_access_export(export, filters=None):
        """
        Generate a PHI access logs export based on filters.
        
        Args:
            export: AuditExport object
            filters: Dictionary of filters to apply
            
        Returns:
            str: File URL if successful, None otherwise
        """
        try:
            # Update status to processing
            export.update_status(AuditExport.Status.PROCESSING)
            
            # Use filters from export object if not provided
            if filters is None:
                filters = export.filters
            
            # Build the queryset with filters
            queryset = PHIAccessLog.objects.all().order_by('-timestamp')
            
            # Apply filters
            queryset = ExportService._apply_phi_access_filters(queryset, filters)
            
            # Generate CSV in memory
            csv_buffer = io.StringIO()
            writer = csv.writer(csv_buffer)
            
            # Write header
            writer.writerow([
                'ID', 'Timestamp', 'User', 'Patient', 'Access Type', 
                'Reason', 'Record Type', 'Record ID', 'IP Address'
            ])
            
            # Write data rows
            for log in queryset.iterator():  # Use iterator for efficiency with large datasets
                writer.writerow([
                    str(log.id),
                    log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    log.user.username if log.user else 'Anonymous',
                    log.patient.username if log.patient else 'Unknown',
                    log.get_access_type_display(),
                    log.reason,
                    log.record_type,
                    log.record_id,
                    log.ip_address
                ])
            
            # Save the file to storage
            file_path = ExportService._generate_safe_filepath(
                prefix='audit_exports/',
                filename=f"phi_access_export_{export.user.username}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )
            
            # Save to storage
            default_storage.save(file_path, ContentFile(csv_buffer.getvalue().encode('utf-8')))
            
            # Set the file URL
            file_url = ExportService._generate_file_url(file_path)
                
            # Update export status
            export.update_status(
                AuditExport.Status.COMPLETED,
                file_url=file_url
            )
            
            # Log the PHI export
            AuditEvent.objects.create(
                user=export.user,
                event_type=AuditEvent.EventType.EXPORT,
                resource_type='phi_access_logs',
                resource_id='export',
                description=f"Generated PHI access export with {queryset.count()} records"
            )
            
            return file_url
            
        except Exception as e:
            logger.error(f"Error generating PHI access export: {str(e)}")
            
            # Update export with error status
            export.update_status(
                AuditExport.Status.FAILED,
                error_message=str(e)
            )
            
            return None
    
    @staticmethod
    def generate_security_audit_export(export, filters=None):
        """
        Generate a security audit logs export based on filters.
        
        Args:
            export: AuditExport object
            filters: Dictionary of filters to apply
            
        Returns:
            str: File URL if successful, None otherwise
        """
        try:
            # Update status to processing
            export.update_status(AuditExport.Status.PROCESSING)
            
            # Use filters from export object if not provided
            if filters is None:
                filters = export.filters
            
            # Build the queryset with filters
            queryset = SecurityAuditLog.objects.all().order_by('-timestamp')
            
            # Apply filters
            queryset = ExportService._apply_security_audit_filters(queryset, filters)
            
            # Generate CSV in memory
            csv_buffer = io.StringIO()
            writer = csv.writer(csv_buffer)
            
            # Write header
            writer.writerow([
                'ID', 'Timestamp', 'User', 'Event Type', 'Severity', 
                'Description', 'IP Address', 'Resolved', 'Resolved By', 
                'Resolved At', 'Resolution Notes'
            ])
            
            # Write data rows
            for log in queryset.iterator():  # Use iterator for efficiency with large datasets
                writer.writerow([
                    str(log.id),
                    log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    log.user.username if log.user else 'Anonymous',
                    log.get_event_type_display(),
                    log.get_severity_display(),
                    log.description,
                    log.ip_address,
                    'Yes' if log.resolved else 'No',
                    log.resolved_by.username if log.resolved_by else '',
                    log.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if log.resolved_at else '',
                    log.resolution_notes
                ])
            
            # Save the file to storage
            file_path = ExportService._generate_safe_filepath(
                prefix='audit_exports/',
                filename=f"security_audit_export_{export.user.username}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )
            
            # Save to storage
            default_storage.save(file_path, ContentFile(csv_buffer.getvalue().encode('utf-8')))
            
            # Set the file URL
            file_url = ExportService._generate_file_url(file_path)
                
            # Update export status
            export.update_status(
                AuditExport.Status.COMPLETED,
                file_url=file_url
            )
            
            # Log the security export
            AuditEvent.objects.create(
                user=export.user,
                event_type=AuditEvent.EventType.EXPORT,
                resource_type='security_audit_logs',
                resource_id='export',
                description=f"Generated security audit export with {queryset.count()} records"
            )
            
            return file_url
            
        except Exception as e:
            logger.error(f"Error generating security audit export: {str(e)}")
            
            # Update export with error status
            export.update_status(
                AuditExport.Status.FAILED,
                error_message=str(e)
            )
            
            return None
    
    @staticmethod
    def _apply_audit_filters(queryset, filters):
        """
        Apply filters to an audit queryset.
        
        Args:
            queryset: Base queryset to filter
            filters: Dictionary of filter criteria
            
        Returns:
            QuerySet: Filtered queryset
        """
        if not filters:
            return queryset
            
        if 'user' in filters and filters['user']:
            queryset = queryset.filter(user__id=filters['user'])
        
        if 'event_type' in filters and filters['event_type']:
            queryset = queryset.filter(event_type=filters['event_type'])
        
        if 'resource_type' in filters and filters['resource_type']:
            queryset = queryset.filter(resource_type=filters['resource_type'])
        
        if 'start_date' in filters and filters['start_date']:
            start_date = parse_date(filters['start_date'])
            if start_date:
                queryset = queryset.filter(timestamp__gte=start_date)
        
        if 'end_date' in filters and filters['end_date']:
            end_date = parse_date(filters['end_date'])
            if end_date:
                # Set to end of day
                end_date = end_date.replace(hour=23, minute=59, second=59)
                queryset = queryset.filter(timestamp__lte=end_date)
        
        if 'search' in filters and filters['search']:
            search = filters['search']
            queryset = queryset.filter(
                Q(description__icontains=search) |
                Q(resource_id__icontains=search) |
                Q(user__username__icontains=search) |
                Q(user__first_name__icontains=search) |
                Q(user__last_name__icontains=search)
            )
        
        if 'ip_address' in filters and filters['ip_address']:
            queryset = queryset.filter(ip_address=filters['ip_address'])
        
        if 'user_role' in filters and filters['user_role']:
            queryset = queryset.filter(user__role=filters['user_role'])
        
        return queryset
    
    @staticmethod
    def _apply_phi_access_filters(queryset, filters):
        """
        Apply filters to a PHI access logs queryset.
        
        Args:
            queryset: Base queryset to filter
            filters: Dictionary of filter criteria
            
        Returns:
            QuerySet: Filtered queryset
        """
        if not filters:
            return queryset
            
        if 'user' in filters and filters['user']:
            queryset = queryset.filter(user__id=filters['user'])
        
        if 'patient' in filters and filters['patient']:
            queryset = queryset.filter(patient__id=filters['patient'])
        
        if 'access_type' in filters and filters['access_type']:
            queryset = queryset.filter(access_type=filters['access_type'])
        
        if 'record_type' in filters and filters['record_type']:
            queryset = queryset.filter(record_type=filters['record_type'])
        
        if 'start_date' in filters and filters['start_date']:
            start_date = parse_date(filters['start_date'])
            if start_date:
                queryset = queryset.filter(timestamp__gte=start_date)
        
        if 'end_date' in filters and filters['end_date']:
            end_date = parse_date(filters['end_date'])
            if end_date:
                # Set to end of day
                end_date = end_date.replace(hour=23, minute=59, second=59)
                queryset = queryset.filter(timestamp__lte=end_date)
        
        if 'search' in filters and filters['search']:
            search = filters['search']
            queryset = queryset.filter(
                Q(reason__icontains=search) |
                Q(record_id__icontains=search) |
                Q(user__username__icontains=search) |
                Q(patient__username__icontains=search)
            )
        
        if 'missing_reason' in filters and filters.get('missing_reason') in ['true', True, 1, '1']:
            queryset = queryset.filter(Q(reason='') | Q(reason='No reason provided'))
        
        if 'user_role' in filters and filters['user_role']:
            queryset = queryset.filter(user__role=filters['user_role'])
        
        if 'ip_address' in filters and filters['ip_address']:
            queryset = queryset.filter(ip_address=filters['ip_address'])
        
        return queryset
    
    @staticmethod
    def _apply_security_audit_filters(queryset, filters):
        """
        Apply filters to a security audit logs queryset.
        
        Args:
            queryset: Base queryset to filter
            filters: Dictionary of filter criteria
            
        Returns:
            QuerySet: Filtered queryset
        """
        if not filters:
            return queryset
            
        if 'user' in filters and filters['user']:
            queryset = queryset.filter(user__id=filters['user'])
        
        if 'event_type' in filters and filters['event_type']:
            queryset = queryset.filter(event_type=filters['event_type'])
        
        if 'severity' in filters and filters['severity']:
            queryset = queryset.filter(severity=filters['severity'])
        
        if 'resolved' in filters:
            resolved = filters['resolved'] in ['true', True, 1, '1']
            queryset = queryset.filter(resolved=resolved)
        
        if 'start_date' in filters and filters['start_date']:
            start_date = parse_date(filters['start_date'])
            if start_date:
                queryset = queryset.filter(timestamp__gte=start_date)
        
        if 'end_date' in filters and filters['end_date']:
            end_date = parse_date(filters['end_date'])
            if end_date:
                # Set to end of day
                end_date = end_date.replace(hour=23, minute=59, second=59)
                queryset = queryset.filter(timestamp__lte=end_date)
        
        if 'search' in filters and filters['search']:
            search = filters['search']
            queryset = queryset.filter(
                Q(description__icontains=search) |
                Q(user__username__icontains=search) |
                Q(ip_address__icontains=search)
            )
        
        if 'ip_address' in filters and filters['ip_address']:
            queryset = queryset.filter(ip_address=filters['ip_address'])
        
        return queryset
        
    @staticmethod
    def _generate_safe_filepath(prefix, filename):
        """
        Generate a safe file path for export storage.
        
        Args:
            prefix: Directory prefix
            filename: Original filename
            
        Returns:
            str: Safe file path
        """
        # Sanitize filename to prevent path traversal
        safe_filename = os.path.basename(filename)
        
        # Ensure directory exists in storage
        if not default_storage.exists(prefix):
            try:
                directory_name, _ = os.path.split(prefix)
                default_storage.mkdir(directory_name)
            except (AttributeError, NotImplementedError):
                # Some storage backends don't support mkdir
                pass
                
        return f"{prefix}{safe_filename}"
        
    @staticmethod
    def _generate_file_url(file_path):
        """
        Generate file URL for the saved export.
        
        Args:
            file_path: Path where file is stored
            
        Returns:
            str: URL for the file
        """
        if hasattr(settings, 'MEDIA_URL'):
            return f"{settings.MEDIA_URL}{file_path}"
        else:
            return file_path
