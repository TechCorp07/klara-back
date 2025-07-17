# security/services/threat_detection.py
import logging
import requests
import hashlib
import ipaddress
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Count, Q
from django.conf import settings
from django.contrib.auth import get_user_model

from ..models import SecurityThreat, NetworkMonitor, FileIntegrityMonitor
from audit.models import AuditEvent, PHIAccessLog, SecurityAuditLog

User = get_user_model()
logger = logging.getLogger('security.threat_detection')


class ThreatDetectionService:
    """
    Service for real-time threat detection and analysis.
    Implements multiple detection algorithms and threat intelligence integration.
    """
    
    def __init__(self):
        self.threat_intel_apis = getattr(settings, 'THREAT_INTEL_APIS', {})
        self.detection_rules = self._load_detection_rules()
    
    @classmethod
    def run_comprehensive_threat_scan(cls):
        """Run comprehensive threat detection across all vectors."""
        service = cls()
        detected_threats = []
        
        logger.info("Starting comprehensive threat detection scan")
        
        try:
            # 1. Behavioral Analysis
            behavioral_threats = service.detect_behavioral_anomalies()
            detected_threats.extend(behavioral_threats)
            
            # 2. Network Analysis
            network_threats = service.analyze_network_traffic()
            detected_threats.extend(network_threats)
            
            # 3. File Integrity Analysis
            file_threats = service.analyze_file_changes()
            detected_threats.extend(file_threats)
            
            # 4. Authentication Analysis
            auth_threats = service.detect_authentication_threats()
            detected_threats.extend(auth_threats)
            
            # 5. Data Access Pattern Analysis
            access_threats = service.detect_suspicious_data_access()
            detected_threats.extend(access_threats)
            
            # 6. Threat Intelligence Correlation
            intel_threats = service.correlate_threat_intelligence()
            detected_threats.extend(intel_threats)
            
            logger.info(f"Threat detection completed: {len(detected_threats)} threats detected")
            
            # Send alerts for critical threats
            critical_threats = [t for t in detected_threats if t.severity == 'critical']
            if critical_threats:
                service._send_critical_threat_alerts(critical_threats)
            
            return detected_threats
            
        except Exception as e:
            logger.error(f"Error during threat detection: {str(e)}")
            return []
    
    def detect_behavioral_anomalies(self):
        """Detect behavioral anomalies that may indicate threats."""
        threats = []
        
        # Time-based analysis window
        end_time = timezone.now()
        analysis_window = end_time - timedelta(hours=24)
        baseline_window = end_time - timedelta(days=30)
        
        # 1. Unusual login patterns
        threats.extend(self._detect_unusual_login_patterns(analysis_window, baseline_window))
        
        # 2. Privilege escalation attempts
        threats.extend(self._detect_privilege_escalation(analysis_window))
        
        # 3. Unusual access volumes
        threats.extend(self._detect_unusual_access_volumes(analysis_window, baseline_window))
        
        # 4. After-hours activity anomalies
        threats.extend(self._detect_after_hours_anomalies(analysis_window))
        
        return threats
    
    def _detect_unusual_login_patterns(self, analysis_window, baseline_window):
        """Detect unusual login patterns and behaviors."""
        threats = []
        
        # Get login events in analysis window
        recent_logins = AuditEvent.objects.filter(
            event_type=AuditEvent.EventType.LOGIN,
            timestamp__gte=analysis_window
        )
        
        # Group by user and analyze patterns
        user_login_patterns = {}
        for login in recent_logins:
            if login.user_id not in user_login_patterns:
                user_login_patterns[login.user_id] = {
                    'login_times': [],
                    'ip_addresses': set(),
                    'user_agents': set(),
                    'total_logins': 0
                }
            
            pattern = user_login_patterns[login.user_id]
            pattern['login_times'].append(login.timestamp)
            pattern['ip_addresses'].add(login.ip_address)
            pattern['user_agents'].add(login.user_agent)
            pattern['total_logins'] += 1
        
        # Analyze each user's patterns
        for user_id, pattern in user_login_patterns.items():
            # Multiple IP addresses in short time
            if len(pattern['ip_addresses']) > 3:
                try:
                    user = User.objects.get(id=user_id)
                    threat = SecurityThreat.objects.create(
                        threat_type=SecurityThreat.ThreatType.SUSPICIOUS_ACTIVITY,
                        severity=SecurityThreat.Severity.MEDIUM,
                        title=f"Multiple IP Login Pattern - {user.username}",
                        description=f"User {user.username} logged in from {len(pattern['ip_addresses'])} different IP addresses in 24 hours",
                        affected_user=user,
                        detection_source="Behavioral Analysis",
                        threat_indicators={
                            'ip_addresses': list(pattern['ip_addresses']),
                            'login_count': pattern['total_logins'],
                            'detection_type': 'multiple_ip_login'
                        }
                    )
                    threats.append(threat)
                except User.DoesNotExist:
                    continue
            
            # Rapid successive logins (potential brute force)
            if pattern['total_logins'] > 20:  # 20+ logins in 24 hours
                try:
                    user = User.objects.get(id=user_id)
                    threat = SecurityThreat.objects.create(
                        threat_type=SecurityThreat.ThreatType.BRUTE_FORCE,
                        severity=SecurityThreat.Severity.HIGH,
                        title=f"Rapid Login Attempts - {user.username}",
                        description=f"User {user.username} had {pattern['total_logins']} login attempts in 24 hours",
                        affected_user=user,
                        detection_source="Behavioral Analysis",
                        threat_indicators={
                            'login_count': pattern['total_logins'],
                            'time_window': '24 hours',
                            'detection_type': 'rapid_login_attempts'
                        }
                    )
                    threats.append(threat)
                except User.DoesNotExist:
                    continue
        
        return threats
    
    def _detect_privilege_escalation(self, analysis_window):
        """Detect potential privilege escalation attempts."""
        threats = []
        
        # Look for permission change events
        permission_changes = AuditEvent.objects.filter(
            event_type=AuditEvent.EventType.PERMISSION_CHANGE,
            timestamp__gte=analysis_window
        )
        
        # Group by user and analyze patterns
        user_changes = {}
        for change in permission_changes:
            if change.user_id not in user_changes:
                user_changes[change.user_id] = []
            user_changes[change.user_id].append(change)
        
        for user_id, changes in user_changes.items():
            if len(changes) > 5:  # Multiple permission changes
                try:
                    user = User.objects.get(id=user_id)
                    threat = SecurityThreat.objects.create(
                        threat_type=SecurityThreat.ThreatType.PRIVILEGE_ESCALATION,
                        severity=SecurityThreat.Severity.HIGH,
                        title=f"Multiple Permission Changes - {user.username}",
                        description=f"User {user.username} had {len(changes)} permission changes in 24 hours",
                        affected_user=user,
                        detection_source="Behavioral Analysis",
                        threat_indicators={
                            'permission_changes': len(changes),
                            'detection_type': 'privilege_escalation'
                        }
                    )
                    threats.append(threat)
                except User.DoesNotExist:
                    continue
        
        return threats
    
    def analyze_network_traffic(self):
        """Analyze network traffic for threats."""
        threats = []
        
        # Get recent network alerts
        recent_alerts = NetworkMonitor.objects.filter(
            timestamp__gte=timezone.now() - timedelta(hours=1),
            is_false_positive=False
        )
        
        # Group by source IP
        ip_activity = {}
        for alert in recent_alerts:
            ip = alert.source_ip
            if ip not in ip_activity:
                ip_activity[ip] = {
                    'alerts': [],
                    'alert_types': set(),
                    'severity_levels': set()
                }
            
            ip_activity[ip]['alerts'].append(alert)
            ip_activity[ip]['alert_types'].add(alert.alert_type)
            ip_activity[ip]['severity_levels'].add(alert.severity)
        
        # Analyze patterns
        for ip, activity in ip_activity.items():
            alert_count = len(activity['alerts'])
            
            # High-volume alerts from single IP
            if alert_count > 10:
                threat = SecurityThreat.objects.create(
                    threat_type=SecurityThreat.ThreatType.DDoS,
                    severity=SecurityThreat.Severity.HIGH,
                    title=f"High-Volume Network Activity from {ip}",
                    description=f"IP {ip} generated {alert_count} network alerts in 1 hour",
                    source_ip=ip,
                    detection_source="Network Analysis",
                    threat_indicators={
                        'alert_count': alert_count,
                        'alert_types': list(activity['alert_types']),
                        'max_severity': max(activity['severity_levels']),
                        'detection_type': 'high_volume_network_activity'
                    }
                )
                threats.append(threat)
            
            # Multiple attack types from single IP
            if len(activity['alert_types']) > 3:
                threat = SecurityThreat.objects.create(
                    threat_type=SecurityThreat.ThreatType.INTRUSION,
                    severity=SecurityThreat.Severity.HIGH,
                    title=f"Multi-Vector Attack from {ip}",
                    description=f"IP {ip} triggered {len(activity['alert_types'])} different attack types",
                    source_ip=ip,
                    detection_source="Network Analysis",
                    threat_indicators={
                        'attack_types': list(activity['alert_types']),
                        'alert_count': alert_count,
                        'detection_type': 'multi_vector_attack'
                    }
                )
                threats.append(threat)
        
        return threats
    
    def analyze_file_changes(self):
        """Analyze file changes for potential threats."""
        threats = []
        
        # Get recent critical file changes
        critical_changes = FileIntegrityMonitor.objects.filter(
            timestamp__gte=timezone.now() - timedelta(hours=24),
            is_critical_file=True,
            is_authorized_change=False
        )
        
        # Group by file path patterns
        system_file_changes = critical_changes.filter(
            file_path__contains='/etc/'
        ).count()
        
        if system_file_changes > 10:
            threat = SecurityThreat.objects.create(
                threat_type=SecurityThreat.ThreatType.SYSTEM_INTRUSION,
                severity=SecurityThreat.Severity.CRITICAL,
                title="Multiple System File Changes Detected",
                description=f"{system_file_changes} unauthorized changes to system files in 24 hours",
                detection_source="File Integrity Monitoring",
                threat_indicators={
                    'system_file_changes': system_file_changes,
                    'detection_type': 'unauthorized_system_changes'
                }
            )
            threats.append(threat)
        
        # Check for suspicious executable changes
        executable_changes = critical_changes.filter(
            Q(file_path__endswith='.exe') |
            Q(file_path__endswith='.bat') |
            Q(file_path__endswith='.sh') |
            Q(file_path__endswith='.py')
        )
        
        if executable_changes.count() > 5:
            threat = SecurityThreat.objects.create(
                threat_type=SecurityThreat.ThreatType.MALWARE,
                severity=SecurityThreat.Severity.HIGH,
                title="Suspicious Executable File Changes",
                description=f"{executable_changes.count()} unauthorized executable file changes detected",
                detection_source="File Integrity Monitoring",
                threat_indicators={
                    'executable_changes': executable_changes.count(),
                    'detection_type': 'suspicious_executable_changes'
                }
            )
            threats.append(threat)
        
        return threats
    
    def detect_authentication_threats(self):
        """Detect authentication-related threats."""
        threats = []
        
        # Get failed login attempts
        failed_logins = AuditEvent.objects.filter(
            event_type=AuditEvent.EventType.ERROR,
            description__icontains='login',
            timestamp__gte=timezone.now() - timedelta(hours=24)
        )
        
        # Group by IP address
        ip_failures = {}
        for failure in failed_logins:
            ip = failure.ip_address
            if ip not in ip_failures:
                ip_failures[ip] = []
            ip_failures[ip].append(failure)
        
        # Detect brute force attempts
        for ip, failures in ip_failures.items():
            if len(failures) > 50:  # 50+ failures in 24 hours
                threat = SecurityThreat.objects.create(
                    threat_type=SecurityThreat.ThreatType.BRUTE_FORCE,
                    severity=SecurityThreat.Severity.HIGH,
                    title=f"Brute Force Attack from {ip}",
                    description=f"IP {ip} had {len(failures)} failed login attempts in 24 hours",
                    source_ip=ip,
                    detection_source="Authentication Analysis",
                    threat_indicators={
                        'failed_attempts': len(failures),
                        'time_window': '24 hours',
                        'detection_type': 'brute_force_authentication'
                    }
                )
                threats.append(threat)
        
        return threats
    
    def detect_suspicious_data_access(self):
        """Detect suspicious patterns in data access."""
        threats = []
        
        # Get PHI access logs
        phi_access = PHIAccessLog.objects.filter(
            timestamp__gte=timezone.now() - timedelta(hours=24)
        )
        
        # Group by user
        user_access = {}
        for access in phi_access:
            if access.user_id not in user_access:
                user_access[access.user_id] = {
                    'total_access': 0,
                    'patients_accessed': set(),
                    'record_types': set(),
                    'access_times': []
                }
            
            user_access[access.user_id]['total_access'] += 1
            user_access[access.user_id]['patients_accessed'].add(access.patient_id)
            user_access[access.user_id]['record_types'].add(access.record_type)
            user_access[access.user_id]['access_times'].append(access.timestamp)
        
        # Analyze patterns
        for user_id, access_data in user_access.items():
            # Unusual volume of patient records accessed
            if len(access_data['patients_accessed']) > 100:
                try:
                    user = User.objects.get(id=user_id)
                    threat = SecurityThreat.objects.create(
                        threat_type=SecurityThreat.ThreatType.DATA_EXFILTRATION,
                        severity=SecurityThreat.Severity.CRITICAL,
                        title=f"Mass Patient Data Access - {user.username}",
                        description=f"User {user.username} accessed {len(access_data['patients_accessed'])} patient records in 24 hours",
                        affected_user=user,
                        detection_source="Data Access Analysis",
                        threat_indicators={
                            'patients_accessed': len(access_data['patients_accessed']),
                            'total_accesses': access_data['total_access'],
                            'detection_type': 'mass_data_access'
                        }
                    )
                    threats.append(threat)
                except User.DoesNotExist:
                    continue
        
        return threats
    
    def correlate_threat_intelligence(self):
        """Correlate indicators with threat intelligence feeds."""
        threats = []
        
        # This would integrate with external threat intelligence APIs
        # For now, implementing basic IP reputation checks
        
        # Get unique source IPs from recent network alerts
        recent_ips = NetworkMonitor.objects.filter(
            timestamp__gte=timezone.now() - timedelta(hours=24)
        ).values_list('source_ip', flat=True).distinct()
        
        for ip in recent_ips:
            reputation = self._check_ip_reputation(ip)
            if reputation and reputation.get('threat_score', 0) > 7:
                threat = SecurityThreat.objects.create(
                    threat_type=SecurityThreat.ThreatType.MALICIOUS_IP,
                    severity=SecurityThreat.Severity.HIGH,
                    title=f"Known Malicious IP Detected: {ip}",
                    description=f"IP {ip} matches threat intelligence indicators",
                    source_ip=ip,
                    detection_source="Threat Intelligence",
                    threat_indicators={
                        'reputation_score': reputation.get('threat_score'),
                        'threat_types': reputation.get('threat_types', []),
                        'detection_type': 'threat_intelligence_match'
                    }
                )
                threats.append(threat)
        
        return threats
    
    def _check_ip_reputation(self, ip_address):
        """Check IP reputation against threat intelligence sources."""
        try:
            # This would integrate with real threat intelligence APIs
            # For demonstration, implementing basic checks
            
            # Check if IP is in private ranges (less suspicious)
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                return {'threat_score': 0, 'threat_types': []}
            
            # Simulate threat intelligence lookup
            # In production, this would call APIs like VirusTotal, AlienVault, etc.
            hash_score = int(hashlib.md5(ip_address.encode()).hexdigest()[:2], 16)
            
            if hash_score > 240:  # ~6% of IPs flagged as high risk
                return {
                    'threat_score': 8,
                    'threat_types': ['malware', 'botnet'],
                    'source': 'simulated_threat_intel'
                }
            elif hash_score > 200:  # ~22% flagged as medium risk
                return {
                    'threat_score': 5,
                    'threat_types': ['scanning'],
                    'source': 'simulated_threat_intel'
                }
            
            return {'threat_score': 0, 'threat_types': []}
            
        except Exception as e:
            logger.error(f"Error checking IP reputation for {ip_address}: {str(e)}")
            return None
    
    def _load_detection_rules(self):
        """Load threat detection rules from configuration."""
        default_rules = {
            'failed_login_threshold': 50,
            'multiple_ip_threshold': 3,
            'permission_change_threshold': 5,
            'system_file_change_threshold': 10,
            'mass_data_access_threshold': 100,
            'network_alert_threshold': 10
        }
        
        return getattr(settings, 'THREAT_DETECTION_RULES', default_rules)
    
    def _send_critical_threat_alerts(self, critical_threats):
        """Send immediate alerts for critical threats."""
        try:
            from django.core.mail import send_mail
            
            admin_emails = getattr(settings, 'SECURITY_ADMIN_EMAILS', [])
            if not admin_emails:
                return
            
            threat_summaries = []
            for threat in critical_threats:
                threat_summaries.append(
                    f"- {threat.title}: {threat.description}"
                )
            
            subject = f"CRITICAL SECURITY ALERT: {len(critical_threats)} threats detected"
            message = f"""
CRITICAL SECURITY THREATS DETECTED

The following critical security threats have been automatically detected:

{chr(10).join(threat_summaries)}

Please investigate immediately through the security dashboard.

This is an automated alert from Klararety Security System.
"""
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=admin_emails,
                fail_silently=True
            )
            
        except Exception as e:
            logger.error(f"Failed to send critical threat alerts: {str(e)}")


class ThreatIntelligenceService:
    """Service for threat intelligence integration and IOC management."""
    
    @staticmethod
    def update_threat_indicators():
        """Update threat indicators from external sources."""
        # This would implement feeds from MISP, STIX/TAXII, etc.
        pass
    
    @staticmethod
    def check_ioc_matches(indicators):
        """Check indicators against known IOCs."""
        # This would check against internal and external IOC databases
        pass
