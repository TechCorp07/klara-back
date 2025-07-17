import os
import sys
import csv
import json
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db.models import Count, Q
from app.audit import settings
from audit.models import (
    AuditEvent, PHIAccessLog, SecurityAuditLog, 
    ComplianceReport, AuditExport
)
from audit.services.hipaa_reports import HIPAAComplianceReporter

User = get_user_model()

class Command(BaseCommand):
    help = 'Admin utility for HIPAA compliance audit management'

    def add_arguments(self, parser):
        # Create subparsers for different operations
        subparsers = parser.add_subparsers(dest='command', help='Commands')
        
        # Export audit logs
        export_parser = subparsers.add_parser('export', help='Export audit logs')
        export_parser.add_argument(
            '--type',
            type=str,
            choices=['events', 'phi', 'security'],
            default='events',
            help='Type of logs to export'
        )
        export_parser.add_argument(
            '--start-date',
            type=str,
            help='Start date (YYYY-MM-DD)'
        )
        export_parser.add_argument(
            '--end-date',
            type=str,
            help='End date (YYYY-MM-DD)'
        )
        export_parser.add_argument(
            '--user',
            type=str,
            help='Filter by username'
        )
        export_parser.add_argument(
            '--output',
            type=str,
            default='audit_export.csv',
            help='Output file path'
        )
        
        # Generate compliance report
        report_parser = subparsers.add_parser('report', help='Generate compliance report')
        report_parser.add_argument(
            '--type',
            type=str,
            choices=['daily', 'phi', 'security', 'user', 'system', 'custom'],
            default='daily',
            help='Type of report to generate'
        )
        report_parser.add_argument(
            '--date',
            type=str,
            help='Report date (YYYY-MM-DD)'
        )
        report_parser.add_argument(
            '--start-date',
            type=str,
            help='Start date for report period (YYYY-MM-DD)'
        )
        report_parser.add_argument(
            '--end-date',
            type=str,
            help='End date for report period (YYYY-MM-DD)'
        )
        report_parser.add_argument(
            '--output',
            type=str,
            help='Output file path'
        )
        
        # Check security events
        security_parser = subparsers.add_parser('security', help='Check security events')
        security_parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Number of days to check'
        )
        security_parser.add_argument(
            '--severity',
            type=str,
            choices=['all', 'high', 'critical'],
            default='all',
            help='Severity level to check'
        )
        security_parser.add_argument(
            '--unresolved',
            action='store_true',
            help='Show only unresolved events'
        )
        
        # User audit analysis
        user_parser = subparsers.add_parser('user', help='Analyze user activity')
        user_parser.add_argument(
            'username',
            type=str,
            help='Username to analyze'
        )
        user_parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days to analyze'
        )
        
        # Suspicious activity check
        suspicious_parser = subparsers.add_parser('suspicious', help='Check for suspicious activity')
        suspicious_parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Number of days to check'
        )
        suspicious_parser.add_argument(
            '--threshold',
            type=int,
            default=20,
            help='Access threshold for flagging'
        )

    def handle(self, *args, **options):
        command = options.get('command')
        
        if not command:
            self.print_help('manage.py', 'audit_admin')
            return
            
        if command == 'export':
            self.export_logs(options)
        elif command == 'report':
            self.generate_report(options)
        elif command == 'security':
            self.check_security(options)
        elif command == 'user':
            self.analyze_user(options)
        elif command == 'suspicious':
            self.check_suspicious(options)
        else:
            self.stdout.write(self.style.ERROR(f"Unknown command: {command}"))

    def export_logs(self, options):
        """Export audit logs based on options."""
        log_type = options.get('type')
        start_date_str = options.get('start_date')
        end_date_str = options.get('end_date')
        username = options.get('user')
        output_file = options.get('output')
        
        # Parse dates
        start_date = None
        end_date = None
        
        if start_date_str:
            try:
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
                start_datetime = datetime.combine(start_date, datetime.min.time())
                start_datetime = timezone.make_aware(start_datetime)
            except ValueError:
                raise CommandError("Invalid start date format. Use YYYY-MM-DD")
        else:
            # Default to 30 days ago
            start_datetime = timezone.now() - timedelta(days=30)
            
        if end_date_str:
            try:
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
                end_datetime = datetime.combine(end_date, datetime.max.time())
                end_datetime = timezone.make_aware(end_datetime)
            except ValueError:
                raise CommandError("Invalid end date format. Use YYYY-MM-DD")
        else:
            # Default to now
            end_datetime = timezone.now()
        
        self.stdout.write(f"Exporting {log_type} from {start_datetime.date()} to {end_datetime.date()}...")
        
        # Set up CSV file
        with open(output_file, 'w', newline='') as csvfile:
            if log_type == 'events':
                self._export_audit_events(csvfile, start_datetime, end_datetime, username)
            elif log_type == 'phi':
                self._export_phi_logs(csvfile, start_datetime, end_datetime, username)
            elif log_type == 'security':
                self._export_security_logs(csvfile, start_datetime, end_datetime, username)
        
        self.stdout.write(self.style.SUCCESS(f"Export completed: {output_file}"))

    def _export_audit_events(self, csvfile, start_datetime, end_datetime, username):
        """Export general audit events to CSV."""
        # Set up query
        query = AuditEvent.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        )
        
        # Filter by username if provided
        if username:
            try:
                user = User.objects.get(username=username)
                query = query.filter(user=user)
            except User.DoesNotExist:
                self.stdout.write(self.style.WARNING(f"User {username} not found. Exporting all events."))
        
        # Order by timestamp
        query = query.order_by('-timestamp')
        
        # Set up CSV writer
        writer = csv.writer(csvfile)
        
        # Write header
        writer.writerow([
            'Timestamp', 'User', 'Event Type', 'Resource Type', 
            'Resource ID', 'Description', 'IP Address'
        ])
        
        # Write data
        for event in query:
            writer.writerow([
                event.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                event.user.username if event.user else 'Anonymous',
                event.get_event_type_display(),
                event.resource_type,
                event.resource_id,
                event.description,
                event.ip_address or 'Unknown'
            ])

    def _export_phi_logs(self, csvfile, start_datetime, end_datetime, username):
        """Export PHI access logs to CSV."""
        # Set up query
        query = PHIAccessLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        )
        
        # Filter by username if provided
        if username:
            try:
                user = User.objects.get(username=username)
                query = query.filter(user=user)
            except User.DoesNotExist:
                self.stdout.write(self.style.WARNING(f"User {username} not found. Exporting all logs."))
        
        # Order by timestamp
        query = query.order_by('-timestamp')
        
        # Set up CSV writer
        writer = csv.writer(csvfile)
        
        # Write header
        writer.writerow([
            'Timestamp', 'User', 'Patient', 'Access Type', 
            'Record Type', 'Record ID', 'Reason', 'IP Address'
        ])
        
        # Write data
        for log in query:
            writer.writerow([
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.user.username if log.user else 'Anonymous',
                log.patient.username if log.patient else 'Unknown',
                log.get_access_type_display(),
                log.record_type,
                log.record_id,
                log.reason,
                log.ip_address or 'Unknown'
            ])

    def _export_security_logs(self, csvfile, start_datetime, end_datetime, username):
        """Export security audit logs to CSV."""
        # Set up query
        query = SecurityAuditLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        )
        
        # Filter by username if provided
        if username:
            try:
                user = User.objects.get(username=username)
                query = query.filter(user=user)
            except User.DoesNotExist:
                self.stdout.write(self.style.WARNING(f"User {username} not found. Exporting all logs."))
        
        # Order by timestamp
        query = query.order_by('-timestamp')
        
        # Set up CSV writer
        writer = csv.writer(csvfile)
        
        # Write header
        writer.writerow([
            'Timestamp', 'User', 'Event Type', 'Severity', 
            'Description', 'IP Address', 'Resolved', 'Resolved By'
        ])
        
        # Write data
        for log in query:
            writer.writerow([
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.user.username if log.user else 'Anonymous',
                log.get_event_type_display(),
                log.get_severity_display(),
                log.description,
                log.ip_address or 'Unknown',
                'Yes' if log.resolved else 'No',
                log.resolved_by.username if log.resolved_by else ''
            ])

    def generate_report(self, options):
        """Generate a compliance report based on options."""
        report_type = options.get('type')
        date_str = options.get('date')
        start_date_str = options.get('start_date')
        end_date_str = options.get('end_date')
        output_file = options.get('output')
        
        # Parse report date
        if date_str:
            try:
                report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            except ValueError:
                raise CommandError("Invalid date format. Use YYYY-MM-DD")
        else:
            # Default to yesterday
            report_date = timezone.now().date() - timedelta(days=1)
            
        # Parse start date
        if start_date_str:
            try:
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            except ValueError:
                raise CommandError("Invalid start date format. Use YYYY-MM-DD")
        else:
            # Default to 30 days before report date
            start_date = report_date - timedelta(days=30)
            
        # Parse end date
        if end_date_str:
            try:
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            except ValueError:
                raise CommandError("Invalid end date format. Use YYYY-MM-DD")
        else:
            # Default to report date
            end_date = report_date
            
        # Map report type to model report type
        report_type_map = {
            'daily': ComplianceReport.ReportType.DAILY_AUDIT,
            'phi': ComplianceReport.ReportType.PHI_ACCESS,
            'security': ComplianceReport.ReportType.SECURITY_INCIDENTS,
            'user': ComplianceReport.ReportType.USER_ACTIVITY,
            'system': ComplianceReport.ReportType.SYSTEM_ACCESS,
            'custom': ComplianceReport.ReportType.CUSTOM
        }
        
        model_report_type = report_type_map[report_type]
        
        # Create report parameters
        parameters = {
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat(),
            'report_name': f"{report_type.capitalize()} Report for {end_date.isoformat()}"
        }
        
        # Create report record
        report = ComplianceReport.objects.create(
            report_type=model_report_type,
            report_date=report_date,
            status=ComplianceReport.Status.PROCESSING,
            parameters=parameters
        )
        
        self.stdout.write(f"Generating {report_type} report for {report_date}...")
        
        # Generate report based on type
        try:
            if report_type == 'daily':
                from audit.tasks import generate_daily_audit_report
                generate_daily_audit_report(report)
            elif report_type == 'phi':
                # Custom PHI access report - get summary from report service
                summary = HIPAAComplianceReporter.generate_phi_access_summary(start_date, end_date)
                
                # Create CSV file
                if output_file:
                    with open(output_file, 'w', newline='') as csvfile:
                        writer = csv.writer(csvfile)
                        
                        # Write header
                        writer.writerow(['PHI Access Report'])
                        writer.writerow([f"Period: {start_date.isoformat()} to {end_date.isoformat()}"])
                        writer.writerow([])
                        
                        # Write summary
                        writer.writerow(['Total PHI Accesses', summary['total_accesses']])
                        writer.writerow([])
                        
                        # Write access by type
                        writer.writerow(['Access by Type'])
                        for access_type, count in summary['access_by_type'].items():
                            writer.writerow([access_type, count])
                        writer.writerow([])
                        
                        # Write access by user role
                        writer.writerow(['Access by User Role'])
                        for role, count in summary['access_by_user_role'].items():
                            writer.writerow([role, count])
                        writer.writerow([])
                        
                        # Write access without reason
                        writer.writerow(['Access Without Reason', summary['missing_reason']])
                        writer.writerow([])
                
                # Update report status
                report.status = ComplianceReport.Status.COMPLETED
                report.notes = f"PHI access report for {start_date.isoformat()} to {end_date.isoformat()}"
                if output_file:
                    report.file_url = output_file
                report.save()
                
                # Display summary
                self.stdout.write("PHI Access Summary:")
                self.stdout.write(f"  Total accesses: {summary['total_accesses']}")
                self.stdout.write(f"  Missing reason: {summary['missing_reason']}")
                
            elif report_type == 'security':
                # Custom security report - get assessment from report service
                assessment = HIPAAComplianceReporter.generate_security_risk_assessment()
                
                # Create JSON file
                if output_file:
                    with open(output_file, 'w') as jsonfile:
                        json.dump(assessment, jsonfile, indent=2)
                
                # Update report status
                report.status = ComplianceReport.Status.COMPLETED
                report.notes = f"Security risk assessment for {report_date.isoformat()}"
                if output_file:
                    report.file_url = output_file
                report.save()
                
                # Display summary
                self.stdout.write("Security Risk Assessment:")
                self.stdout.write(f"  Risk score: {assessment['overall_risk_score']} ({assessment['risk_level']})")
                self.stdout.write(f"  Recent incidents: {assessment['recent_incidents_count']}")
                self.stdout.write(f"  Unresolved critical: {assessment['unresolved_critical_count']}")
                
            else:
                self.stdout.write(self.style.WARNING(f"Report type '{report_type}' not implemented. Creating placeholder."))
                
                # Update report status
                report.status = ComplianceReport.Status.COMPLETED
                report.notes = f"Placeholder for {report_type} report"
                report.save()
            
            self.stdout.write(self.style.SUCCESS(f"Report generated successfully (ID: {report.id})"))
            
        except Exception as e:
            # Update report status on error
            report.status = ComplianceReport.Status.FAILED
            report.notes = f"Error: {str(e)}"
            report.save()
            
            self.stdout.write(self.style.ERROR(f"Error generating report: {str(e)}"))

    def check_security(self, options):
        """Check security events based on options."""
        days = options.get('days')
        severity = options.get('severity')
        unresolved_only = options.get('unresolved')
        
        # Calculate time window
        end_datetime = timezone.now()
        start_datetime = end_datetime - timedelta(days=days)
        
        # Build query
        query = SecurityAuditLog.objects.filter(
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        )
        
        # Filter by severity
        if severity == 'high':
            query = query.filter(severity=SecurityAuditLog.Severity.HIGH)
        elif severity == 'critical':
            query = query.filter(severity=SecurityAuditLog.Severity.CRITICAL)
        
        # Filter by resolution status
        if unresolved_only:
            query = query.filter(resolved=False)
        
        # Order by timestamp
        query = query.order_by('-timestamp')
        
        # Display header
        self.stdout.write("")
        self.stdout.write(self.style.HTTP_INFO(f"Security Events - Past {days} Days"))
        self.stdout.write(f"Time period: {start_datetime.date()} to {end_datetime.date()}")
        self.stdout.write(f"Severity: {severity}")
        self.stdout.write(f"Unresolved only: {unresolved_only}")
        self.stdout.write("")
        
        # Count by severity
        if severity == 'all':
            severity_counts = query.values('severity').annotate(count=Count('id'))
            self.stdout.write("Severity breakdown:")
            for item in severity_counts:
                severity_display = dict(SecurityAuditLog.Severity.choices).get(item['severity'], item['severity'])
                self.stdout.write(f"  {severity_display}: {item['count']}")
            self.stdout.write("")
        
        # Count by event type
        event_type_counts = query.values('event_type').annotate(count=Count('id'))
        self.stdout.write("Event type breakdown:")
        for item in event_type_counts:
            event_type_display = dict(SecurityAuditLog.EventType.choices).get(item['event_type'], item['event_type'])
            self.stdout.write(f"  {event_type_display}: {item['count']}")
        self.stdout.write("")
        
        # Display events (limit to 20)
        events = query[:20]
        if events:
            self.stdout.write("Recent security events:")
            for event in events:
                timestamp = event.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                severity_style = self.style.SUCCESS
                if event.severity == SecurityAuditLog.Severity.MEDIUM:
                    severity_style = self.style.WARNING
                elif event.severity == SecurityAuditLog.Severity.HIGH:
                    severity_style = self.style.ERROR
                elif event.severity == SecurityAuditLog.Severity.CRITICAL:
                    severity_style = self.style.ERROR
                
                self.stdout.write(f"  [{timestamp}] {severity_style(event.get_severity_display())}: {event.description}")
        else:
            self.stdout.write("No security events found")

    def analyze_user(self, options):
        """Analyze user activity based on options."""
        username = options.get('username')
        days = options.get('days')
        
        # Get user
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError(f"User {username} not found")
        
        # Calculate time window
        end_datetime = timezone.now()
        start_datetime = end_datetime - timedelta(days=days)
        
        # Get audit events
        audit_events = AuditEvent.objects.filter(
            user=user,
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        )
        
        # Get PHI access logs
        phi_logs = PHIAccessLog.objects.filter(
            user=user,
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        )
        
        # Get security events
        security_events = SecurityAuditLog.objects.filter(
            user=user,
            timestamp__gte=start_datetime,
            timestamp__lte=end_datetime
        )
        
        # Display header
        self.stdout.write("")
        self.stdout.write(self.style.HTTP_INFO(f"User Activity Analysis - {username}"))
        self.stdout.write(f"Time period: {start_datetime.date()} to {end_datetime.date()}")
        self.stdout.write(f"User role: {user.role}")
        self.stdout.write("")
        
        # Display summary counts
        self.stdout.write(f"Total audit events: {audit_events.count()}")
        self.stdout.write(f"Total PHI accesses: {phi_logs.count()}")
        self.stdout.write(f"Total security events: {security_events.count()}")
        self.stdout.write("")
        
        # Break down audit events by type
        event_type_counts = audit_events.values('event_type').annotate(count=Count('id'))
        if event_type_counts:
            self.stdout.write("Audit events by type:")
            for item in event_type_counts:
                event_type_display = dict(AuditEvent.EventType.choices).get(item['event_type'], item['event_type'])
                self.stdout.write(f"  {event_type_display}: {item['count']}")
            self.stdout.write("")
        
        # Break down PHI access by type
        access_type_counts = phi_logs.values('access_type').annotate(count=Count('id'))
        if access_type_counts:
            self.stdout.write("PHI access by type:")
            for item in access_type_counts:
                access_type_display = dict(PHIAccessLog.AccessType.choices).get(item['access_type'], item['access_type'])
                self.stdout.write(f"  {access_type_display}: {item['count']}")
            self.stdout.write("")
            
        # Break down PHI access by record type
        record_type_counts = phi_logs.values('record_type').annotate(count=Count('id'))
        if record_type_counts:
            self.stdout.write("PHI access by record type:")
            for item in record_type_counts:
                self.stdout.write(f"  {item['record_type']}: {item['count']}")
            self.stdout.write("")
            
        # Show recent PHI access
        recent_phi = phi_logs.order_by('-timestamp')[:10]
        if recent_phi:
            self.stdout.write("Recent PHI accesses:")
            for log in recent_phi:
                timestamp = log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                patient_name = log.patient.username if log.patient else 'Unknown'
                self.stdout.write(f"  [{timestamp}] {log.get_access_type_display()} of {log.record_type} for patient {patient_name}")
            self.stdout.write("")
            
        # Show security events
        if security_events:
            self.stdout.write("Security events:")
            for event in security_events.order_by('-timestamp')[:10]:
                timestamp = event.timestamp.strftime('%Y-%m-%d %H:%M:%S')
                severity_style = self.style.SUCCESS
                if event.severity == SecurityAuditLog.Severity.MEDIUM:
                    severity_style = self.style.WARNING
                elif event.severity in [SecurityAuditLog.Severity.HIGH, SecurityAuditLog.Severity.CRITICAL]:
                    severity_style = self.style.ERROR
                
                self.stdout.write(f"  [{timestamp}] {severity_style(event.get_severity_display())}: {event.description}")
            self.stdout.write("")
            
        # Check for potential issues
        issues = []
        
        # Issue 1: PHI access without reason
        phi_no_reason = phi_logs.filter(Q(reason='') | Q(reason='No reason provided')).count()
        if phi_no_reason > 0:
            percent = (phi_no_reason / phi_logs.count() * 100) if phi_logs.count() > 0 else 0
            issues.append(f"PHI accessed without reason {phi_no_reason} times ({percent:.1f}%)")
            
        # Issue 2: Accessing many patients (if provider)
        if user.role == 'provider':
            patient_count = phi_logs.values('patient').distinct().count()
            if patient_count > 20:  # Arbitrary threshold
                issues.append(f"Accessed {patient_count} different patients (high volume)")
                
        # Issue 3: Security violations
        violations = security_events.filter(
            event_type=SecurityAuditLog.EventType.PERMISSION_VIOLATION
        ).count()
        if violations > 0:
            issues.append(f"Has {violations} permission violation events")
            
        # Issue 4: Failed logins
        failed_logins = security_events.filter(
            event_type=SecurityAuditLog.EventType.LOGIN_FAILED
        ).count()
        if failed_logins > 3:  # Arbitrary threshold
            issues.append(f"Has {failed_logins} failed login attempts")
        
        # Display potential issues
        if issues:
            self.stdout.write(self.style.WARNING("Potential Issues:"))
            for issue in issues:
                self.stdout.write(f"  - {issue}")
        else:
            self.stdout.write(self.style.SUCCESS("No significant issues identified."))

    def check_suspicious(self, options):
        """Check for suspicious activity patterns."""
        days = options.get('days')
        threshold = options.get('threshold')
        
        # Calculate time window
        end_datetime = timezone.now()
        start_datetime = end_datetime - timedelta(days=days)
        
        self.stdout.write("")
        self.stdout.write(self.style.HTTP_INFO("Suspicious Activity Analysis"))
        self.stdout.write(f"Time period: {start_datetime.date()} to {end_datetime.date()}")
        self.stdout.write("")
        
        # Check 1: High volume PHI access
        high_volume_users = PHIAccessLog.objects.filter(
            timestamp__gte=start_datetime
        ).values('user').annotate(
            access_count=Count('id')
        ).filter(
            access_count__gt=threshold
        ).order_by('-access_count')
        
        if high_volume_users:
            self.stdout.write(self.style.WARNING("Users with high volume PHI access:"))
            for item in high_volume_users:
                if not item['user']:
                    continue  # Skip anonymous users
                try:
                    user = User.objects.get(id=item['user'])
                    self.stdout.write(f"  {user.username} ({user.role}): {item['access_count']} accesses")
                except User.DoesNotExist:
                    self.stdout.write(f"  Unknown user (ID: {item['user']}): {item['access_count']} accesses")
            self.stdout.write("")
        else:
            self.stdout.write("No users with suspicious high volume access.")
            self.stdout.write("")
        
        # Check 2: Users accessing many different patients
        users_many_patients = PHIAccessLog.objects.filter(
            timestamp__gte=start_datetime
        ).values('user').annotate(
            patient_count=Count('patient', distinct=True)
        ).filter(
            patient_count__gt=threshold
        ).order_by('-patient_count')
        
        if users_many_patients:
            self.stdout.write(self.style.WARNING("Users accessing many different patients:"))
            for item in users_many_patients:
                if not item['user']:
                    continue  # Skip anonymous users
                try:
                    user = User.objects.get(id=item['user'])
                    # Skip for roles that typically access many patients
                    if user.role in ['admin', 'compliance']:
                        continue
                    self.stdout.write(f"  {user.username} ({user.role}): {item['patient_count']} patients")
                except User.DoesNotExist:
                    self.stdout.write(f"  Unknown user (ID: {item['user']}): {item['patient_count']} patients")
            self.stdout.write("")
        else:
            self.stdout.write("No users accessing suspicious numbers of patients.")
            self.stdout.write("")
        
        # Check 3: After hours access
        business_hours_start = getattr(settings, 'BUSINESS_HOURS_START', 8)  # 8 AM default
        business_hours_end = getattr(settings, 'BUSINESS_HOURS_END', 18)     # 6 PM default
        weekend_days = getattr(settings, 'WEEKEND_DAYS', [5, 6])             # Saturday, Sunday
        
        # This query is more complex and needs to be done in Python
        after_hours_counts = {}
        
        # Get all access events
        phi_logs = PHIAccessLog.objects.filter(timestamp__gte=start_datetime)
        
        for log in phi_logs:
            # Skip patients accessing their own data
            if log.user and log.patient and log.user.id == log.patient.id:
                continue
                
            # Check if this is an after-hours access
            access_time = log.timestamp
            is_weekend = access_time.weekday() in weekend_days
            is_after_hours = access_time.hour < business_hours_start or access_time.hour >= business_hours_end
            
            if is_weekend or is_after_hours:
                user_id = log.user.id if log.user else 'anonymous'
                if user_id not in after_hours_counts:
                    after_hours_counts[user_id] = 0
                after_hours_counts[user_id] += 1
        
        # Filter to users above threshold
        suspicious_after_hours = {k: v for k, v in after_hours_counts.items() if v > threshold/2}  # Lower threshold
        
        if suspicious_after_hours:
            self.stdout.write(self.style.WARNING("Users with after-hours access:"))
            for user_id, count in sorted(suspicious_after_hours.items(), key=lambda x: x[1], reverse=True):
                if user_id == 'anonymous':
                    self.stdout.write(f"  Anonymous: {count} accesses")
                    continue
                    
                try:
                    user = User.objects.get(id=user_id)
                    # Skip for roles that typically need after-hours access
                    if user.role in ['admin', 'emergency_provider']:
                        continue
                    self.stdout.write(f"  {user.username} ({user.role}): {count} after-hours accesses")
                except User.DoesNotExist:
                    self.stdout.write(f"  Unknown user (ID: {user_id}): {count} after-hours accesses")
            self.stdout.write("")
        else:
            self.stdout.write("No users with suspicious after-hours access.")
            self.stdout.write("")
        
        # Check 4: Rapid access to many records (potential unauthorized bulk export)
        # Group by user, hour window
        from django.db.models.functions import Extract
        
        rapid_access = PHIAccessLog.objects.filter(
            timestamp__gte=start_datetime
        ).annotate(
            hour=Extract('timestamp', 'hour'),
            day=Extract('timestamp', 'day'),
            month=Extract('timestamp', 'month'),
            year=Extract('timestamp', 'year')
        ).values(
            'user', 'hour', 'day', 'month', 'year'
        ).annotate(
            access_count=Count('id')
        ).filter(
            access_count__gt=threshold*2  # Higher threshold for rapid access
        )
        
        if rapid_access:
            self.stdout.write(self.style.WARNING("Users with rapid access patterns:"))
            for item in rapid_access:
                if not item['user']:
                    continue
                try:
                    user = User.objects.get(id=item['user'])
                    date_str = f"{item['year']}-{item['month']}-{item['day']} {item['hour']}:00"
                    self.stdout.write(f"  {user.username} ({user.role}): {item['access_count']} accesses in hour window {date_str}")
                except User.DoesNotExist:
                    self.stdout.write(f"  Unknown user (ID: {item['user']}): {item['access_count']} accesses")
            self.stdout.write("")
        else:
            self.stdout.write("No users with suspicious rapid access patterns.")
            self.stdout.write("")
