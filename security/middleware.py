# security/middleware.py
import logging
import time
import json
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.contrib.auth import get_user_model

from .models import SecurityThreat, NetworkMonitor
from .services.threat_detection import ThreatDetectionService

User = get_user_model()
logger = logging.getLogger('security.middleware')


class SecurityMonitoringMiddleware:
    """
    Middleware for real-time security monitoring and threat prevention.
    Monitors requests for suspicious patterns and potential attacks.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Load configuration
        self.monitoring_enabled = getattr(settings, 'SECURITY_MONITORING_ENABLED', True)
        self.rate_limit_enabled = getattr(settings, 'SECURITY_RATE_LIMITING_ENABLED', True)
        self.threat_detection_enabled = getattr(settings, 'SECURITY_THREAT_DETECTION_ENABLED', True)
        
        # Rate limiting thresholds
        self.rate_limits = getattr(settings, 'SECURITY_RATE_LIMITS', {
            'requests_per_minute': 60,
            'failed_logins_per_hour': 10,
            'api_calls_per_minute': 100
        })
        
        # Suspicious patterns
        self.suspicious_patterns = [
            # SQL injection patterns
            r'union\s+select',
            r'drop\s+table',
            r'insert\s+into',
            r'delete\s+from',
            
            # XSS patterns
            r'<script',
            r'javascript:',
            r'onerror\s*=',
            r'onload\s*=',
            
            # Path traversal
            r'\.\./\.\.',
            r'\.\.\\\.\.\\',
            
            # Command injection
            r';\s*rm\s+',
            r';\s*cat\s+',
            r';\s*ls\s+',
            r'&&\s*rm\s+',
        ]
        
        # Compile patterns for performance
        import re
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.suspicious_patterns]
    
    def __call__(self, request):
        """Process request through security monitoring."""
        if not self.monitoring_enabled:
            return self.get_response(request)
        
        # Record request start time
        start_time = time.time()
        
        # Pre-request security checks
        security_check_result = self._perform_security_checks(request)
        
        if security_check_result['blocked']:
            logger.warning(f"Blocked request from {self._get_client_ip(request)}: {security_check_result['reason']}")
            return HttpResponseForbidden(f"Request blocked: {security_check_result['reason']}")
        
        # Process request
        response = self.get_response(request)
        
        # Post-request monitoring
        self._post_request_monitoring(request, response, start_time)
        
        return response
    
    def _perform_security_checks(self, request):
        """Perform pre-request security checks."""
        client_ip = self._get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Check if IP is blacklisted
        if self._is_ip_blacklisted(client_ip):
            return {'blocked': True, 'reason': 'IP address blacklisted'}
        
        # Rate limiting checks
        if self.rate_limit_enabled:
            rate_limit_result = self._check_rate_limits(request, client_ip)
            if rate_limit_result['exceeded']:
                return {'blocked': True, 'reason': f"Rate limit exceeded: {rate_limit_result['type']}"}
        
        # Suspicious pattern detection
        if self.threat_detection_enabled:
            pattern_result = self._check_suspicious_patterns(request)
            if pattern_result['detected']:
                # Log threat but don't block (configurable)
                self._log_suspicious_activity(request, pattern_result)
                
                # Only block if configured to do so
                if getattr(settings, 'SECURITY_BLOCK_SUSPICIOUS_PATTERNS', False):
                    return {'blocked': True, 'reason': 'Suspicious pattern detected'}
        
        # Check for automated/bot behavior
        bot_result = self._detect_bot_behavior(request, client_ip, user_agent)
        if bot_result['is_bot'] and bot_result['malicious']:
            return {'blocked': True, 'reason': 'Malicious bot detected'}
        
        return {'blocked': False, 'reason': None}
    
    def _check_rate_limits(self, request, client_ip):
        """Check various rate limits."""
        current_time = timezone.now()
        
        # General request rate limiting
        request_key = f"security:rate_limit:requests:{client_ip}"
        request_count = cache.get(request_key, 0)
        
        if request_count >= self.rate_limits['requests_per_minute']:
            return {'exceeded': True, 'type': 'requests_per_minute'}
        
        # Increment counter
        cache.set(request_key, request_count + 1, 60)  # 1 minute TTL
        
        # API-specific rate limiting
        if request.path.startswith('/api/'):
            api_key = f"security:rate_limit:api:{client_ip}"
            api_count = cache.get(api_key, 0)
            
            if api_count >= self.rate_limits['api_calls_per_minute']:
                return {'exceeded': True, 'type': 'api_calls_per_minute'}
            
            cache.set(api_key, api_count + 1, 60)
        
        # Failed login rate limiting
        if request.path in ['/api/users/login/', '/api/auth/login/']:
            login_key = f"security:rate_limit:login:{client_ip}"
            login_count = cache.get(login_key, 0)
            
            if login_count >= self.rate_limits['failed_logins_per_hour']:
                return {'exceeded': True, 'type': 'failed_logins_per_hour'}
        
        return {'exceeded': False, 'type': None}
    
    def _check_suspicious_patterns(self, request):
        """Check request for suspicious patterns."""
        # Check query parameters
        query_string = request.GET.urlencode()
        for pattern in self.compiled_patterns:
            if pattern.search(query_string):
                return {
                    'detected': True,
                    'location': 'query_parameters',
                    'pattern': pattern.pattern,
                    'content': query_string[:200]  # Limit logged content
                }
        
        # Check POST data if present
        if hasattr(request, 'body') and request.body:
            try:
                body_str = request.body.decode('utf-8', errors='ignore')
                for pattern in self.compiled_patterns:
                    if pattern.search(body_str):
                        return {
                            'detected': True,
                            'location': 'request_body',
                            'pattern': pattern.pattern,
                            'content': body_str[:200]
                        }
            except Exception:
                pass
        
        # Check headers
        for header_name, header_value in request.META.items():
            if isinstance(header_value, str):
                for pattern in self.compiled_patterns:
                    if pattern.search(header_value):
                        return {
                            'detected': True,
                            'location': f'header_{header_name}',
                            'pattern': pattern.pattern,
                            'content': header_value[:200]
                        }
        
        return {'detected': False}
    
    def _detect_bot_behavior(self, request, client_ip, user_agent):
        """Detect bot behavior and determine if malicious."""
        # Common bot indicators
        bot_indicators = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
            'python-requests', 'python-urllib', 'automation'
        ]
        
        is_bot = any(indicator in user_agent.lower() for indicator in bot_indicators)
        
        # Check for rapid requests from same IP
        rapid_requests_key = f"security:rapid_requests:{client_ip}"
        request_times = cache.get(rapid_requests_key, [])
        current_time = time.time()
        
        # Remove old entries (older than 60 seconds)
        request_times = [t for t in request_times if current_time - t < 60]
        request_times.append(current_time)
        
        cache.set(rapid_requests_key, request_times, 60)
        
        # More than 30 requests per minute indicates bot behavior
        if len(request_times) > 30:
            is_bot = True
        
        # Determine if malicious
        malicious = False
        if is_bot:
            # Check for suspicious paths
            suspicious_paths = [
                '/admin/', '/.env', '/wp-admin/', '/phpmyadmin/',
                '/config/', '/backup/', '/test/', '/debug/'
            ]
            
            if any(request.path.startswith(path) for path in suspicious_paths):
                malicious = True
            
            # Check for excessive requests
            if len(request_times) > 60:  # More than 1 request per second
                malicious = True
        
        return {'is_bot': is_bot, 'malicious': malicious, 'request_rate': len(request_times)}
    
    def _is_ip_blacklisted(self, ip_address):
        """Check if IP address is blacklisted."""
        # Check cache first
        blacklist_key = f"security:blacklist:{ip_address}"
        is_blacklisted = cache.get(blacklist_key)
        
        if is_blacklisted is not None:
            return is_blacklisted
        
        # Check if IP has recent critical threats
        recent_threats = SecurityThreat.objects.filter(
            source_ip=ip_address,
            detection_time__gte=timezone.now() - timedelta(hours=24),
            severity__in=['critical', 'high']
        ).count()
        
        # Blacklist if multiple critical threats
        is_blacklisted = recent_threats >= 3
        
        # Cache result for 1 hour
        cache.set(blacklist_key, is_blacklisted, 3600)
        
        return is_blacklisted
    
    def _log_suspicious_activity(self, request, pattern_result):
        """Log suspicious activity as security threat."""
        try:
            client_ip = self._get_client_ip(request)
            user = request.user if hasattr(request, 'user') and request.user.is_authenticated else None
            
            # Create security threat
            threat = SecurityThreat.objects.create(
                threat_type=SecurityThreat.ThreatType.SUSPICIOUS_ACTIVITY,
                severity=SecurityThreat.Severity.MEDIUM,
                title=f"Suspicious Pattern Detected: {pattern_result['pattern'][:50]}",
                description=f"Suspicious pattern detected in {pattern_result['location']}: {pattern_result['pattern']}",
                source_ip=client_ip,
                affected_user=user,
                detection_source="Security Middleware",
                threat_indicators={
                    'pattern': pattern_result['pattern'],
                    'location': pattern_result['location'],
                    'content_sample': pattern_result['content'],
                    'request_path': request.path,
                    'request_method': request.method,
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')
                }
            )
            
            logger.warning(f"Suspicious activity detected: {threat.id}")
            
        except Exception as e:
            logger.error(f"Error logging suspicious activity: {str(e)}")
    
    def _post_request_monitoring(self, request, response, start_time):
        """Perform post-request monitoring and logging."""
        try:
            processing_time = time.time() - start_time
            client_ip = self._get_client_ip(request)
            
            # Log slow requests (potential DoS)
            if processing_time > 10:  # Requests taking longer than 10 seconds
                self._log_slow_request(request, response, processing_time)
            
            # Monitor failed authentication attempts
            if response.status_code == 401 or response.status_code == 403:
                self._monitor_auth_failures(request, client_ip)
            
            # Log high-privilege operations
            if (hasattr(request, 'user') and request.user.is_authenticated and 
                request.user.role in ['admin', 'superuser']):
                self._log_admin_activity(request, response)
            
            # Monitor API abuse
            if (request.path.startswith('/api/') and 
                response.status_code in [429, 500, 502, 503, 504]):
                self._monitor_api_abuse(request, response, client_ip)
            
        except Exception as e:
            logger.error(f"Error in post-request monitoring: {str(e)}")
    
    def _log_slow_request(self, request, response, processing_time):
        """Log slow requests that might indicate DoS attacks."""
        try:
            client_ip = self._get_client_ip(request)
            
            # Check if this IP has multiple slow requests
            slow_requests_key = f"security:slow_requests:{client_ip}"
            slow_count = cache.get(slow_requests_key, 0)
            cache.set(slow_requests_key, slow_count + 1, 3600)  # 1 hour TTL
            
            if slow_count >= 5:  # 5 or more slow requests from same IP
                SecurityThreat.objects.create(
                    threat_type=SecurityThreat.ThreatType.DDoS,
                    severity=SecurityThreat.Severity.MEDIUM,
                    title=f"Potential DoS Attack from {client_ip}",
                    description=f"Multiple slow requests detected from {client_ip} ({slow_count + 1} requests)",
                    source_ip=client_ip,
                    detection_source="Security Middleware",
                    threat_indicators={
                        'slow_request_count': slow_count + 1,
                        'latest_processing_time': processing_time,
                        'request_path': request.path
                    }
                )
        except Exception as e:
            logger.error(f"Error logging slow request: {str(e)}")
    
    def _monitor_auth_failures(self, request, client_ip):
        """Monitor authentication failures for brute force detection."""
        try:
            # Track failed login attempts
            failed_login_key = f"security:failed_logins:{client_ip}"
            failed_count = cache.get(failed_login_key, 0)
            cache.set(failed_login_key, failed_count + 1, 3600)  # 1 hour TTL
            
            # Create threat after threshold
            if failed_count >= self.rate_limits['failed_logins_per_hour']:
                SecurityThreat.objects.create(
                    threat_type=SecurityThreat.ThreatType.BRUTE_FORCE,
                    severity=SecurityThreat.Severity.HIGH,
                    title=f"Brute Force Attack Detected from {client_ip}",
                    description=f"Multiple authentication failures from {client_ip} ({failed_count + 1} attempts)",
                    source_ip=client_ip,
                    detection_source="Security Middleware",
                    threat_indicators={
                        'failed_attempts': failed_count + 1,
                        'time_window': '1 hour',
                        'attack_type': 'brute_force_login'
                    }
                )
        except Exception as e:
            logger.error(f"Error monitoring auth failures: {str(e)}")
    
    def _log_admin_activity(self, request, response):
        """Log administrative user activity."""
        try:
            # Log privileged operations to security audit
            from audit.models import SecurityAuditLog
            
            SecurityAuditLog.objects.create(
                user=request.user,
                event_type=SecurityAuditLog.EventType.SECURITY_CHANGE,
                description=f"Admin action: {request.method} {request.path}",
                severity=SecurityAuditLog.Severity.LOW,
                ip_address=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                additional_data={
                    'request_method': request.method,
                    'request_path': request.path,
                    'response_status': response.status_code
                }
            )
        except Exception as e:
            logger.error(f"Error logging admin activity: {str(e)}")
    
    def _monitor_api_abuse(self, request, response, client_ip):
        """Monitor API abuse patterns."""
        try:
            # Track API errors from same IP
            api_error_key = f"security:api_errors:{client_ip}"
            error_count = cache.get(api_error_key, 0)
            cache.set(api_error_key, error_count + 1, 3600)
            
            # Create threat if many errors
            if error_count >= 20:  # 20 API errors in 1 hour
                SecurityThreat.objects.create(
                    threat_type=SecurityThreat.ThreatType.SUSPICIOUS_ACTIVITY,
                    severity=SecurityThreat.Severity.MEDIUM,
                    title=f"API Abuse Detected from {client_ip}",
                    description=f"Multiple API errors from {client_ip} ({error_count + 1} errors)",
                    source_ip=client_ip,
                    detection_source="Security Middleware",
                    threat_indicators={
                        'api_error_count': error_count + 1,
                        'latest_status_code': response.status_code,
                        'latest_endpoint': request.path
                    }
                )
        except Exception as e:
            logger.error(f"Error monitoring API abuse: {str(e)}")
    
    def _get_client_ip(self, request):
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip


class SecurityResponseMiddleware:
    """
    Middleware for security response headers and protection.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Add security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none';"
        )
        
        # Add HSTS header for HTTPS
        if request.is_secure():
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        return response