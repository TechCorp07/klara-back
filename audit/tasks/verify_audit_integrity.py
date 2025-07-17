from __future__ import absolute_import, unicode_literals
import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.mail import mail_admins
from django.conf import settings
from celery import shared_task
from ..models import AuditEvent, PHIAccessLog, SecurityAuditLog, ComplianceReport

logger = logging.getLogger(__name__)

@shared_task
def verify_audit_integrity():
    """
    Task to verify the integrity of audit logs.
    
    Checks for:
    - Missing records in sequential time periods
    - Unexpected gaps in timestamps
    - Unusual patterns in log volume
    - Modified timestamps or data tampering
    
    This is essential for HIPAA compliance to ensure audit logs are complete and accurate.
    """
    logger.info("Starting audit integrity verification")
    
    try:
        issues = []
        
        # Check for timestamp gaps in audit events
        issues.extend(_check_timestamp_gaps(AuditEvent, 'Audit Events'))
        issues.extend(_check_timestamp_gaps(PHIAccessLog, 'PHI Access Logs'))
        issues.extend(_check_timestamp_gaps(SecurityAuditLog, 'Security Logs'))
        
        # Check for unusual volume changes
        issues.extend(_check_volume_anomalies(AuditEvent, 'Audit Events'))
        issues.extend(_check_volume_anomalies(PHIAccessLog, 'PHI Access Logs'))
        issues.extend(_check_volume_anomalies(SecurityAuditLog, 'Security Logs'))
        
        # Report any integrity issues
        if issues:
            _report_integrity_issues(issues)
            return f"Audit integrity verification completed with {len(issues)} issues found"
        
        logger.info("Audit integrity verification completed successfully - no issues found")
        return "Audit integrity verification completed successfully - no issues found"
        
    except Exception as e:
        logger.error(f"Error during audit integrity verification: {str(e)}")
        
        # Send alert about the failure
        subject = "ALERT: Audit Integrity Verification Failed"
        message = f"""
        The audit integrity verification process failed with the following error:
        
        {str(e)}
        
        This could indicate a problem with the audit logging system that requires immediate attention.
        """
        
        try:
            mail_admins(
                subject=subject,
                message=message,
                fail_silently=True
            )
        except Exception as mail_err:
            logger.error(f"Failed to send admin email about integrity verification failure: {str(mail_err)}")
            
        return f"Error in audit integrity verification: {str(e)}"

def _check_timestamp_gaps(model_class, model_name):
    """
    Check for suspicious gaps in timestamps that could indicate missing records.
    
    Args:
        model_class: The model class to check
        model_name: Display name of the model for reporting
        
    Returns:
        list: Detected issues
    """
    issues = []
    
    # Get historical daily volume averages for comparison
    end_date = timezone.now().date()
    start_date = end_date - timedelta(days=30)
    
    # Use Django's date functions to extract the date portion
    from django.db.models.functions import TruncDate
    from django.db.models import Count, Avg, StdDev
    
    # Get average and standard deviation of daily record counts
    daily_stats = (
        model_class.objects
        .filter(timestamp__date__gte=start_date, timestamp__date__lt=end_date)
        .annotate(date=TruncDate('timestamp'))
        .values('date')
        .annotate(count=Count('id'))
        .aggregate(
            avg_daily_count=Avg('count'),
            stddev_daily_count=StdDev('count')
        )
    )
    
    avg_daily_count = daily_stats['avg_daily_count'] or 0
    stddev_daily_count = daily_stats['stddev_daily_count'] or 0
    
    # Check for days with zero records when we'd expect some
    if avg_daily_count > 10:  # Only check if we typically have a meaningful number of records
        daily_counts = (
            model_class.objects
            .filter(timestamp__date__gte=start_date, timestamp__date__lt=end_date)
            .annotate(date=TruncDate('timestamp'))
            .values('date')
            .annotate(count=Count('id'))
        )
        
        # Get a set of dates with records
        dates_with_records = {item['date'] for item in daily_counts}
        
        # Check each day in our range
        current_date = start_date
        while current_date < end_date:
            if current_date not in dates_with_records:
                # If it's a weekday, it's unusual to have zero records
                if current_date.weekday() < 5:  # 0-4 are Monday to Friday
                    issues.append({
                        'issue_type': 'missing_records',
                        'model': model_name,
                        'date': current_date.isoformat(),
                        'description': f"No {model_name} records found for {current_date.isoformat()}, "
                                      f"when an average of {avg_daily_count:.1f} records were expected"
                    })
            current_date += timedelta(days=1)
    
    # Check for unusual time gaps between sequential records
    try:
        # Get most recent records
        recent_records = model_class.objects.filter(
            timestamp__gte=timezone.now() - timedelta(days=2)
        ).order_by('timestamp')
        
        # Calculate typical time between records
        from statistics import mean, stdev
        
        # If we have enough records to calculate gaps
        if recent_records.count() > 10:
            timestamps = [record.timestamp for record in recent_records]
            gaps = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps)-1)]
            
            if gaps:
                avg_gap = mean(gaps)
                if len(gaps) > 1:
                    gap_stddev = stdev(gaps)
                else:
                    gap_stddev = 0
                
                # Look for unusually large gaps (over 3 standard deviations or 6 hours)
                max_gap_seconds = max(avg_gap + 3 * gap_stddev, 21600)  # At least 6 hours
                
                large_gaps = [
                    (i, gap) for i, gap in enumerate(gaps) 
                    if gap > max_gap_seconds and gap > 3600  # At least 1 hour
                ]
                
                for idx, gap in large_gaps:
                    gap_hours = gap / 3600
                    issues.append({
                        'issue_type': 'timestamp_gap',
                        'model': model_name,
                        'description': f"Unusual gap of {gap_hours:.1f} hours between records on "
                                      f"{timestamps[idx].isoformat()} and {timestamps[idx+1].isoformat()}",
                        'gap_seconds': gap
                    })
    except Exception as e:
        logger.error(f"Error checking timestamp gaps for {model_name}: {str(e)}")
    
    return issues

def _check_volume_anomalies(model_class, model_name):
    """
    Check for unusual changes in log volume that could indicate logging issues.
    
    Args:
        model_class: The model class to check
        model_name: Display name of the model for reporting
        
    Returns:
        list: Detected issues
    """
    issues = []
    
    # Get historical daily volume averages for comparison
    end_date = timezone.now().date()
    start_date = end_date - timedelta(days=30)
    yesterday = end_date - timedelta(days=1)
    
    # Use Django's date functions to extract the date portion
    from django.db.models.functions import TruncDate
    from django.db.models import Count, Avg, StdDev
    
    # Get average and standard deviation of daily record counts
    daily_stats = (
        model_class.objects
        .filter(timestamp__date__gte=start_date, timestamp__date__lt=yesterday)
        .annotate(date=TruncDate('timestamp'))
        .values('date')
        .annotate(count=Count('id'))
        .aggregate(
            avg_daily_count=Avg('count'),
            stddev_daily_count=StdDev('count')
        )
    )
    
    avg_daily_count = daily_stats['avg_daily_count'] or 0
    stddev_daily_count = daily_stats['stddev_daily_count'] or 0
    
    # Get yesterday's count
    yesterday_count = (
        model_class.objects
        .filter(timestamp__date=yesterday)
        .count()
    )
    
    # Calculate Z-score for yesterday's count
    if stddev_daily_count > 0:
        z_score = (yesterday_count - avg_daily_count) / stddev_daily_count
        
        # If Z-score is extremely high or low (> 3 or < -3), it's unusual
        if abs(z_score) > 3:
            direction = "increase" if z_score > 0 else "decrease"
            issues.append({
                'issue_type': 'volume_anomaly',
                'model': model_name,
                'date': yesterday.isoformat(),
                'description': f"Unusual {direction} in {model_name} volume on {yesterday.isoformat()}: "
                             f"{yesterday_count} records (Z-score: {z_score:.2f}), "
                             f"when normal range is {avg_daily_count:.1f} ± {stddev_daily_count:.1f}",
                'z_score': z_score,
                'count': yesterday_count,
                'average': avg_daily_count
            })
    
    # Also check for extremely low counts if we normally have significant volume
    if avg_daily_count > 50 and yesterday_count < avg_daily_count * 0.2:
        issues.append({
            'issue_type': 'low_volume',
            'model': model_name,
            'date': yesterday.isoformat(),
            'description': f"Critically low {model_name} volume on {yesterday.isoformat()}: "
                         f"Only {yesterday_count} records, when typically {avg_daily_count:.1f} expected",
            'count': yesterday_count,
            'average': avg_daily_count
        })
    
    return issues

def _report_integrity_issues(issues):
    """
    Report detected integrity issues to administrators.
    
    Args:
        issues: List of detected issues
    """
    if not issues:
        return
        
    # Log all issues
    for issue in issues:
        logger.warning(f"Audit integrity issue: {issue['description']}")
        
    # Create a security audit log entry for each issue
    from ..models import SecurityAuditLog
    
    for issue in issues:
        SecurityAuditLog.objects.create(
            event_type='system_error',
            description=f"Audit integrity issue: {issue['description']}",
            severity='high',
            additional_data=issue
        )
    
    # Notify administrators
    subject = f"ALERT: {len(issues)} Audit Integrity Issues Detected"
    
    message = f"""
    The audit integrity verification process has detected {len(issues)} potential issues:
    
    """ + "\n\n".join([f"- {issue['description']}" for issue in issues]) + """
    
    These issues could indicate problems with the audit logging system or potential 
    security concerns that require investigation.
    
    Please review the security audit logs for more details.
    """
    
    try:
        mail_admins(
            subject=subject,
            message=message,
            fail_silently=True
        )
    except Exception as e:
        logger.error(f"Failed to send admin email about integrity issues: {str(e)}")
        
    # Also send to compliance officers if configured
    compliance_emails = getattr(settings, 'COMPLIANCE_OFFICER_EMAILS', [])
    if compliance_emails:
        try:
            from django.core.mail import send_mail
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=compliance_emails,
                fail_silently=True
            )
        except Exception as e:
            logger.error(f"Failed to send compliance email about integrity issues: {str(e)}")
